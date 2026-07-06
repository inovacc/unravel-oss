"""Interactive quiz application with scoring and categories.

Covers: NamedTuple, frozen dataclass, __post_init__,
        random.shuffle, zip, map/filter, counter pattern,
        string formatting, multiline strings, dict comprehension.
"""

from __future__ import annotations

import json
import random
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import NamedTuple


class Difficulty(Enum):
    """Question difficulty levels."""

    EASY = auto()
    MEDIUM = auto()
    HARD = auto()

    @property
    def points(self) -> int:
        return {Difficulty.EASY: 10, Difficulty.MEDIUM: 20, Difficulty.HARD: 30}[self]


class Category(Enum):
    """Quiz categories."""

    SCIENCE = "Science"
    HISTORY = "History"
    GEOGRAPHY = "Geography"
    TECHNOLOGY = "Technology"
    LITERATURE = "Literature"
    MATH = "Math"


class Answer(NamedTuple):
    """A single answer option."""

    text: str
    is_correct: bool


@dataclass(frozen=True)
class Question:
    """An immutable quiz question."""

    text: str
    answers: tuple[Answer, ...]
    category: Category
    difficulty: Difficulty
    explanation: str = ""

    def __post_init__(self) -> None:
        correct = sum(1 for a in self.answers if a.is_correct)
        if correct != 1:
            raise ValueError(f"Question must have exactly 1 correct answer, got {correct}")
        if len(self.answers) < 2:
            raise ValueError("Question must have at least 2 answers")

    @property
    def correct_answer(self) -> Answer:
        return next(a for a in self.answers if a.is_correct)

    @property
    def correct_index(self) -> int:
        return next(i for i, a in enumerate(self.answers) if a.is_correct)

    def shuffled(self) -> Question:
        """Return a copy with shuffled answer order."""
        answers = list(self.answers)
        random.shuffle(answers)
        return Question(
            text=self.text,
            answers=tuple(answers),
            category=self.category,
            difficulty=self.difficulty,
            explanation=self.explanation,
        )

    def check(self, answer_index: int) -> bool:
        """Check if the given index is the correct answer."""
        if 0 <= answer_index < len(self.answers):
            return self.answers[answer_index].is_correct
        return False


@dataclass
class QuizResult:
    """Result of answering a question."""

    question: Question
    selected_index: int
    correct: bool
    time_taken_ms: int = 0

    @property
    def points_earned(self) -> int:
        return self.question.difficulty.points if self.correct else 0


@dataclass
class QuizSession:
    """A quiz session tracking progress and score."""

    player_name: str
    questions: list[Question] = field(default_factory=list)
    results: list[QuizResult] = field(default_factory=list)
    current_index: int = 0

    @property
    def total_questions(self) -> int:
        return len(self.questions)

    @property
    def answered(self) -> int:
        return len(self.results)

    @property
    def remaining(self) -> int:
        return self.total_questions - self.answered

    @property
    def score(self) -> int:
        return sum(r.points_earned for r in self.results)

    @property
    def max_score(self) -> int:
        return sum(q.difficulty.points for q in self.questions)

    @property
    def percentage(self) -> float:
        if self.max_score == 0:
            return 0.0
        return (self.score / self.max_score) * 100

    @property
    def correct_count(self) -> int:
        return sum(1 for r in self.results if r.correct)

    @property
    def current_question(self) -> Question | None:
        if self.current_index < len(self.questions):
            return self.questions[self.current_index]
        return None

    @property
    def is_complete(self) -> bool:
        return self.current_index >= len(self.questions)

    def answer(self, answer_index: int, time_ms: int = 0) -> QuizResult:
        """Answer the current question."""
        if self.is_complete:
            raise RuntimeError("Quiz is already complete")
        question = self.questions[self.current_index]
        correct = question.check(answer_index)
        result = QuizResult(
            question=question,
            selected_index=answer_index,
            correct=correct,
            time_taken_ms=time_ms,
        )
        self.results.append(result)
        self.current_index += 1
        return result

    def stats_by_category(self) -> dict[Category, dict[str, int]]:
        """Get stats grouped by category."""
        stats: dict[Category, dict[str, int]] = {}
        for result in self.results:
            cat = result.question.category
            if cat not in stats:
                stats[cat] = {"correct": 0, "total": 0, "points": 0}
            stats[cat]["total"] += 1
            if result.correct:
                stats[cat]["correct"] += 1
                stats[cat]["points"] += result.points_earned
        return stats

    def stats_by_difficulty(self) -> dict[Difficulty, dict[str, int]]:
        """Get stats grouped by difficulty."""
        stats: dict[Difficulty, dict[str, int]] = {}
        for result in self.results:
            diff = result.question.difficulty
            if diff not in stats:
                stats[diff] = {"correct": 0, "total": 0}
            stats[diff]["total"] += 1
            if result.correct:
                stats[diff]["correct"] += 1
        return stats


class QuestionBank:
    """Collection of questions with filtering."""

    def __init__(self) -> None:
        self._questions: list[Question] = []

    def add(self, question: Question) -> None:
        self._questions.append(question)

    def add_many(self, questions: list[Question]) -> None:
        self._questions.extend(questions)

    def __len__(self) -> int:
        return len(self._questions)

    def by_category(self, category: Category) -> list[Question]:
        return [q for q in self._questions if q.category == category]

    def by_difficulty(self, difficulty: Difficulty) -> list[Question]:
        return [q for q in self._questions if q.difficulty == difficulty]

    def random_selection(
        self,
        count: int,
        category: Category | None = None,
        difficulty: Difficulty | None = None,
    ) -> list[Question]:
        """Select random questions with optional filtering."""
        pool = self._questions
        if category is not None:
            pool = [q for q in pool if q.category == category]
        if difficulty is not None:
            pool = [q for q in pool if q.difficulty == difficulty]
        count = min(count, len(pool))
        return random.sample(pool, count)

    def category_counts(self) -> dict[Category, int]:
        """Count questions per category."""
        counter: Counter[Category] = Counter(q.category for q in self._questions)
        return dict(counter)

    def difficulty_counts(self) -> dict[Difficulty, int]:
        """Count questions per difficulty."""
        counter: Counter[Difficulty] = Counter(q.difficulty for q in self._questions)
        return dict(counter)

    def to_json(self) -> str:
        """Serialize question bank to JSON."""
        questions = []
        for q in self._questions:
            questions.append({
                "text": q.text,
                "answers": [{"text": a.text, "is_correct": a.is_correct} for a in q.answers],
                "category": q.category.value,
                "difficulty": q.difficulty.name,
                "explanation": q.explanation,
            })
        return json.dumps({"questions": questions}, indent=2)

    @classmethod
    def from_json(cls, data: str) -> QuestionBank:
        """Deserialize question bank from JSON."""
        bank = cls()
        parsed = json.loads(data)
        for entry in parsed.get("questions", []):
            answers = tuple(
                Answer(text=a["text"], is_correct=a["is_correct"])
                for a in entry["answers"]
            )
            category_map = {c.value: c for c in Category}
            question = Question(
                text=entry["text"],
                answers=answers,
                category=category_map[entry["category"]],
                difficulty=Difficulty[entry["difficulty"]],
                explanation=entry.get("explanation", ""),
            )
            bank.add(question)
        return bank


@dataclass
class Leaderboard:
    """Track high scores."""

    entries: list[tuple[str, int, float]] = field(default_factory=list)

    def add_score(self, name: str, score: int, percentage: float) -> int:
        """Add a score and return the rank (1-based)."""
        self.entries.append((name, score, percentage))
        self.entries.sort(key=lambda e: (-e[1], -e[2]))
        return next(
            i + 1 for i, e in enumerate(self.entries)
            if e[0] == name and e[1] == score
        )

    def top(self, n: int = 10) -> list[tuple[str, int, float]]:
        """Get top N entries."""
        return self.entries[:n]

    def format(self) -> str:
        """Format leaderboard as a string."""
        lines = [f"{'Rank':<6} {'Name':<20} {'Score':>6} {'%':>7}"]
        lines.append("-" * 42)
        for i, (name, score, pct) in enumerate(self.entries[:10], 1):
            lines.append(f"{i:<6} {name:<20} {score:>6} {pct:>6.1f}%")
        return "\n".join(lines)
