"""A machine learning pipeline framework with metaclasses, descriptors, ABC, and multiple inheritance.

Demonstrates: metaclasses, descriptors, ABC, multiple inheritance, __init_subclass__,
              class decorators, advanced typing, generic classes.
Difficulty: Very Hard (~400 LOC)
"""

from __future__ import annotations

import hashlib
import json
import math
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, ClassVar, Generic, TypeVar

T = TypeVar("T")
M = TypeVar("M")


# --- Descriptors ---

class ValidatedField:
    """Descriptor that validates field values on assignment."""

    def __init__(self, field_type: type, min_val: float | None = None, max_val: float | None = None) -> None:
        self._field_type = field_type
        self._min_val = min_val
        self._max_val = max_val
        self._name = ""

    def __set_name__(self, owner: type, name: str) -> None:
        self._name = name

    def __get__(self, obj: Any, objtype: type | None = None) -> Any:
        if obj is None:
            return self
        return obj.__dict__.get(self._name)

    def __set__(self, obj: Any, value: Any) -> None:
        if not isinstance(value, self._field_type):
            raise TypeError(
                f"{self._name} must be {self._field_type.__name__}, got {type(value).__name__}"
            )
        if self._min_val is not None and value < self._min_val:
            raise ValueError(f"{self._name} must be >= {self._min_val}, got {value}")
        if self._max_val is not None and value > self._max_val:
            raise ValueError(f"{self._name} must be <= {self._max_val}, got {value}")
        obj.__dict__[self._name] = value


class CachedProperty:
    """Descriptor that computes a property once and caches the result."""

    def __init__(self, func: Any) -> None:
        self._func = func
        self._name = ""

    def __set_name__(self, owner: type, name: str) -> None:
        self._name = f"_cached_{name}"

    def __get__(self, obj: Any, objtype: type | None = None) -> Any:
        if obj is None:
            return self
        if not hasattr(obj, self._name):
            setattr(obj, self._name, self._func(obj))
        return getattr(obj, self._name)


# --- Metaclass ---

class ModelRegistryMeta(type):
    """Metaclass that automatically registers model classes in a global registry."""

    _registry: ClassVar[dict[str, type]] = {}

    def __new__(mcs, name: str, bases: tuple[type, ...], namespace: dict[str, Any]) -> type:
        cls = super().__new__(mcs, name, bases, namespace)
        if name != "BaseModel" and not name.startswith("_"):
            mcs._registry[name] = cls
        return cls

    @classmethod
    def get_model(mcs, name: str) -> type | None:
        return mcs._registry.get(name)

    @classmethod
    def list_models(mcs) -> list[str]:
        return sorted(mcs._registry.keys())


# --- Abstract base classes ---

class Estimator(ABC):
    """Abstract base for all estimators."""

    @abstractmethod
    def fit(self, x: list[list[float]], y: list[float]) -> Estimator:
        ...

    @abstractmethod
    def predict(self, x: list[list[float]]) -> list[float]:
        ...


class Transformer(ABC):
    """Abstract base for data transformers."""

    @abstractmethod
    def fit(self, x: list[list[float]]) -> Transformer:
        ...

    @abstractmethod
    def transform(self, x: list[list[float]]) -> list[list[float]]:
        ...


class Scorer(ABC):
    """Abstract base for model scoring."""

    @abstractmethod
    def score(self, y_true: list[float], y_pred: list[float]) -> float:
        ...


# --- Mixins (multiple inheritance) ---

class SerializableMixin:
    """Mixin providing JSON serialization."""

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"__class__": type(self).__name__}
        for key, value in self.__dict__.items():
            if not key.startswith("_"):
                result[key] = value
        return result

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, default=str)


class LoggableMixin:
    """Mixin providing execution logging."""

    _log: list[str] = []

    def log(self, message: str) -> None:
        entry = f"[{type(self).__name__}] {message}"
        self._log.append(entry)

    def get_log(self) -> list[str]:
        return list(self._log)


# --- init_subclass ---

class BaseModel(metaclass=ModelRegistryMeta):
    """Base class for ML models using __init_subclass__ for auto-configuration."""

    model_type: ClassVar[str] = "base"
    version: ClassVar[str] = "1.0"

    def __init_subclass__(cls, model_type: str = "unknown", **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        cls.model_type = model_type

    def model_id(self) -> str:
        """Generate a unique model identifier."""
        data = f"{type(self).__name__}:{self.model_type}:{self.version}"
        return hashlib.md5(data.encode()).hexdigest()[:12]


# --- Concrete implementations ---

@dataclass
class DataPoint:
    features: list[float]
    label: float = 0.0


class StandardScaler(Transformer, SerializableMixin, LoggableMixin):
    """Standardizes features by removing mean and scaling to unit variance."""

    def __init__(self) -> None:
        self._means: list[float] = []
        self._stds: list[float] = []
        self._fitted = False

    def fit(self, x: list[list[float]]) -> StandardScaler:
        if not x:
            raise ValueError("Cannot fit on empty data")

        n_features = len(x[0])
        n_samples = len(x)
        self._means = [0.0] * n_features
        self._stds = [0.0] * n_features

        # Compute means
        for row in x:
            for j, val in enumerate(row):
                self._means[j] += val
        self._means = [m / n_samples for m in self._means]

        # Compute standard deviations
        for row in x:
            for j, val in enumerate(row):
                self._stds[j] += (val - self._means[j]) ** 2
        self._stds = [math.sqrt(s / n_samples) if s > 0 else 1.0 for s in self._stds]

        self._fitted = True
        self.log(f"Fitted on {n_samples} samples with {n_features} features")
        return self

    def transform(self, x: list[list[float]]) -> list[list[float]]:
        if not self._fitted:
            raise RuntimeError("Scaler must be fitted before transform")

        result: list[list[float]] = []
        for row in x:
            scaled = [
                (val - self._means[j]) / self._stds[j]
                for j, val in enumerate(row)
            ]
            result.append(scaled)

        self.log(f"Transformed {len(x)} samples")
        return result


class LinearRegression(BaseModel, Estimator, SerializableMixin, LoggableMixin, model_type="linear"):
    """Simple linear regression using gradient descent."""

    learning_rate = ValidatedField(float, min_val=0.0001, max_val=1.0)
    n_iterations = ValidatedField(int, min_val=1, max_val=100000)

    def __init__(self, learning_rate: float = 0.01, n_iterations: int = 1000) -> None:
        self.learning_rate = learning_rate
        self.n_iterations = n_iterations
        self._weights: list[float] = []
        self._bias: float = 0.0
        self._fitted = False

    def fit(self, x: list[list[float]], y: list[float]) -> LinearRegression:
        n_samples = len(x)
        n_features = len(x[0]) if x else 0

        self._weights = [0.0] * n_features
        self._bias = 0.0

        for iteration in range(self.n_iterations):
            # Forward pass
            predictions = self._forward(x)

            # Compute gradients
            dw = [0.0] * n_features
            db = 0.0

            for i in range(n_samples):
                error = predictions[i] - y[i]
                for j in range(n_features):
                    dw[j] += error * x[i][j]
                db += error

            # Update weights
            for j in range(n_features):
                self._weights[j] -= (self.learning_rate * dw[j]) / n_samples
            self._bias -= (self.learning_rate * db) / n_samples

            if iteration % 100 == 0:
                loss = sum((p - t) ** 2 for p, t in zip(predictions, y)) / n_samples
                self.log(f"Iteration {iteration}: loss={loss:.6f}")

        self._fitted = True
        self.log(f"Fitted on {n_samples} samples")
        return self

    def predict(self, x: list[list[float]]) -> list[float]:
        if not self._fitted:
            raise RuntimeError("Model must be fitted before prediction")
        return self._forward(x)

    def _forward(self, x: list[list[float]]) -> list[float]:
        predictions: list[float] = []
        for row in x:
            pred = self._bias
            for j, val in enumerate(row):
                pred += self._weights[j] * val
            predictions.append(pred)
        return predictions

    @CachedProperty
    def n_parameters(self) -> int:
        return len(self._weights) + 1  # weights + bias


class MSEScorer(Scorer, SerializableMixin):
    """Mean Squared Error scorer."""

    def score(self, y_true: list[float], y_pred: list[float]) -> float:
        if len(y_true) != len(y_pred):
            raise ValueError("Length mismatch between y_true and y_pred")
        n = len(y_true)
        if n == 0:
            return 0.0
        return sum((t - p) ** 2 for t, p in zip(y_true, y_pred)) / n


class R2Scorer(Scorer, SerializableMixin):
    """R-squared (coefficient of determination) scorer."""

    def score(self, y_true: list[float], y_pred: list[float]) -> float:
        if len(y_true) != len(y_pred):
            raise ValueError("Length mismatch")
        n = len(y_true)
        if n == 0:
            return 0.0

        mean_y = sum(y_true) / n
        ss_res = sum((t - p) ** 2 for t, p in zip(y_true, y_pred))
        ss_tot = sum((t - mean_y) ** 2 for t in y_true)

        if ss_tot == 0:
            return 1.0 if ss_res == 0 else 0.0
        return 1.0 - (ss_res / ss_tot)


# --- Pipeline ---

@dataclass
class PipelineStep:
    name: str
    component: Any
    elapsed_ms: float = 0.0


class MLPipeline(SerializableMixin, LoggableMixin):
    """Composable ML pipeline with fit/predict interface."""

    def __init__(self, name: str) -> None:
        self.name = name
        self._steps: list[PipelineStep] = []
        self._fitted = False

    def add_transformer(self, name: str, transformer: Transformer) -> MLPipeline:
        self._steps.append(PipelineStep(name=name, component=transformer))
        return self

    def add_estimator(self, name: str, estimator: Estimator) -> MLPipeline:
        self._steps.append(PipelineStep(name=name, component=estimator))
        return self

    def fit(self, x: list[list[float]], y: list[float]) -> MLPipeline:
        current_x = x
        self.log(f"Fitting pipeline '{self.name}' with {len(self._steps)} steps")

        for step in self._steps:
            start = time.monotonic()

            if isinstance(step.component, Transformer):
                step.component.fit(current_x)
                current_x = step.component.transform(current_x)
            elif isinstance(step.component, Estimator):
                step.component.fit(current_x, y)

            step.elapsed_ms = (time.monotonic() - start) * 1000
            self.log(f"Step '{step.name}' fitted in {step.elapsed_ms:.2f}ms")

        self._fitted = True
        return self

    def predict(self, x: list[list[float]]) -> list[float]:
        if not self._fitted:
            raise RuntimeError("Pipeline must be fitted before prediction")

        current_x = x
        predictions: list[float] = []

        for step in self._steps:
            if isinstance(step.component, Transformer):
                current_x = step.component.transform(current_x)
            elif isinstance(step.component, Estimator):
                predictions = step.component.predict(current_x)

        return predictions

    def evaluate(self, x: list[list[float]], y: list[float], scorer: Scorer) -> float:
        predictions = self.predict(x)
        return scorer.score(y, predictions)


def generate_data(n_samples: int = 100, n_features: int = 2, noise: float = 0.1) -> tuple[list[list[float]], list[float]]:
    """Generate synthetic linear regression data."""
    import random
    random.seed(42)

    true_weights = [random.uniform(-2, 2) for _ in range(n_features)]
    true_bias = random.uniform(-1, 1)

    x: list[list[float]] = []
    y: list[float] = []

    for _ in range(n_samples):
        row = [random.gauss(0, 1) for _ in range(n_features)]
        label = true_bias + sum(w * v for w, v in zip(true_weights, row))
        label += random.gauss(0, noise)
        x.append(row)
        y.append(label)

    return x, y


def main() -> None:
    print("Registered models:", ModelRegistryMeta.list_models())
    print()

    # Generate data
    x_train, y_train = generate_data(n_samples=200, n_features=3, noise=0.5)
    x_test, y_test = generate_data(n_samples=50, n_features=3, noise=0.5)

    # Build pipeline
    pipeline = MLPipeline("regression_v1")
    pipeline.add_transformer("scaler", StandardScaler())
    pipeline.add_estimator("regressor", LinearRegression(learning_rate=0.01, n_iterations=500))

    # Train
    pipeline.fit(x_train, y_train)

    # Evaluate
    mse_scorer = MSEScorer()
    r2_scorer = R2Scorer()

    mse = pipeline.evaluate(x_test, y_test, mse_scorer)
    r2 = pipeline.evaluate(x_test, y_test, r2_scorer)

    print(f"Pipeline: {pipeline.name}")
    print(f"  MSE:  {mse:.6f}")
    print(f"  R2:   {r2:.6f}")

    # Model info
    model = LinearRegression()
    print(f"\nModel ID: {model.model_id()}")
    print(f"Model type: {model.model_type}")
    print(f"Version: {model.version}")

    # Serialization
    print(f"\nPipeline JSON:\n{pipeline.to_json()}")

    # Log
    print("\nExecution log:")
    for entry in pipeline.get_log():
        print(f"  {entry}")


if __name__ == "__main__":
    main()
