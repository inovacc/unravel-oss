"""Stock portfolio tracker with moving averages and alerts.

Covers: decimal module, statistics module, property setters,
        __format__, slots with inheritance, weakref,
        bisect for sorted insertion, named constants.
"""

from __future__ import annotations

import bisect
import statistics
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from decimal import Decimal, ROUND_HALF_UP
from enum import Enum, auto
from typing import Iterator


# Named constants
TRADING_DAYS_PER_YEAR = 252
DEFAULT_COMMISSION = Decimal("9.99")
TWO_PLACES = Decimal("0.01")


class Currency(Enum):
    """Supported currencies."""

    USD = "USD"
    EUR = "EUR"
    GBP = "GBP"
    BRL = "BRL"


class OrderSide(Enum):
    """Order side."""

    BUY = auto()
    SELL = auto()


class AlertCondition(Enum):
    """Price alert conditions."""

    ABOVE = auto()
    BELOW = auto()
    PERCENT_CHANGE = auto()


def money(value: str | float | int) -> Decimal:
    """Create a monetary Decimal value rounded to 2 places."""
    return Decimal(str(value)).quantize(TWO_PLACES, rounding=ROUND_HALF_UP)


@dataclass(slots=True)
class PricePoint:
    """A single price data point."""

    date: date
    open: Decimal
    high: Decimal
    low: Decimal
    close: Decimal
    volume: int

    @property
    def range(self) -> Decimal:
        return self.high - self.low

    @property
    def change(self) -> Decimal:
        return self.close - self.open

    @property
    def change_pct(self) -> Decimal:
        if self.open == 0:
            return Decimal("0")
        return ((self.close - self.open) / self.open * 100).quantize(TWO_PLACES)

    def __format__(self, spec: str) -> str:
        if spec == "short":
            return f"{self.date} ${self.close}"
        return f"{self.date} O:{self.open} H:{self.high} L:{self.low} C:{self.close} V:{self.volume}"


@dataclass(slots=True)
class Order:
    """A buy or sell order."""

    symbol: str
    side: OrderSide
    quantity: int
    price: Decimal
    commission: Decimal = DEFAULT_COMMISSION
    executed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def total_cost(self) -> Decimal:
        base = self.price * self.quantity
        if self.side == OrderSide.BUY:
            return (base + self.commission).quantize(TWO_PLACES)
        return (base - self.commission).quantize(TWO_PLACES)

    @property
    def cost_per_share(self) -> Decimal:
        if self.quantity == 0:
            return Decimal("0")
        return (self.total_cost / self.quantity).quantize(TWO_PLACES)


class PriceHistory:
    """Price history for a stock with technical indicators."""

    def __init__(self, symbol: str) -> None:
        self.symbol = symbol
        self._prices: list[PricePoint] = []

    def add(self, point: PricePoint) -> None:
        """Add price point, maintaining sorted order by date."""
        dates = [p.date for p in self._prices]
        idx = bisect.bisect_left(dates, point.date)
        if idx < len(self._prices) and self._prices[idx].date == point.date:
            self._prices[idx] = point
        else:
            self._prices.insert(idx, point)

    def __len__(self) -> int:
        return len(self._prices)

    def __iter__(self) -> Iterator[PricePoint]:
        yield from self._prices

    def __getitem__(self, index: int) -> PricePoint:
        return self._prices[index]

    @property
    def latest(self) -> PricePoint | None:
        return self._prices[-1] if self._prices else None

    @property
    def highest(self) -> PricePoint | None:
        return max(self._prices, key=lambda p: p.high) if self._prices else None

    @property
    def lowest(self) -> PricePoint | None:
        return min(self._prices, key=lambda p: p.low) if self._prices else None

    def closing_prices(self, last_n: int | None = None) -> list[Decimal]:
        prices = [p.close for p in self._prices]
        if last_n is not None:
            return prices[-last_n:]
        return prices

    def sma(self, period: int) -> Decimal | None:
        """Simple Moving Average."""
        closes = self.closing_prices(period)
        if len(closes) < period:
            return None
        total = sum(closes)
        return (total / period).quantize(TWO_PLACES)

    def ema(self, period: int) -> Decimal | None:
        """Exponential Moving Average."""
        closes = self.closing_prices()
        if len(closes) < period:
            return None
        multiplier = Decimal(2) / (period + 1)
        ema_val = sum(closes[:period]) / period
        for price in closes[period:]:
            ema_val = (price - ema_val) * multiplier + ema_val
        return ema_val.quantize(TWO_PLACES)

    def volatility(self, period: int = 20) -> float | None:
        """Historical volatility (standard deviation of returns)."""
        closes = self.closing_prices(period + 1)
        if len(closes) < 2:
            return None
        returns = [
            float((closes[i] - closes[i - 1]) / closes[i - 1])
            for i in range(1, len(closes))
        ]
        if len(returns) < 2:
            return None
        return statistics.stdev(returns)

    def rsi(self, period: int = 14) -> Decimal | None:
        """Relative Strength Index."""
        closes = self.closing_prices(period + 1)
        if len(closes) < period + 1:
            return None
        gains: list[Decimal] = []
        losses: list[Decimal] = []
        for i in range(1, len(closes)):
            diff = closes[i] - closes[i - 1]
            if diff > 0:
                gains.append(diff)
                losses.append(Decimal("0"))
            else:
                gains.append(Decimal("0"))
                losses.append(abs(diff))
        avg_gain = sum(gains) / len(gains)
        avg_loss = sum(losses) / len(losses)
        if avg_loss == 0:
            return Decimal("100")
        rs = avg_gain / avg_loss
        rsi_val = Decimal("100") - (Decimal("100") / (1 + rs))
        return rsi_val.quantize(TWO_PLACES)


@dataclass
class Position:
    """A stock position in the portfolio."""

    symbol: str
    quantity: int = 0
    avg_cost: Decimal = Decimal("0")
    currency: Currency = Currency.USD

    @property
    def total_cost_basis(self) -> Decimal:
        return (self.avg_cost * self.quantity).quantize(TWO_PLACES)

    def market_value(self, current_price: Decimal) -> Decimal:
        return (current_price * self.quantity).quantize(TWO_PLACES)

    def unrealized_pnl(self, current_price: Decimal) -> Decimal:
        return (self.market_value(current_price) - self.total_cost_basis).quantize(TWO_PLACES)

    def unrealized_pnl_pct(self, current_price: Decimal) -> Decimal:
        if self.total_cost_basis == 0:
            return Decimal("0")
        return (self.unrealized_pnl(current_price) / self.total_cost_basis * 100).quantize(TWO_PLACES)


class Portfolio:
    """Stock portfolio with positions and order tracking."""

    def __init__(self, name: str, cash: Decimal = Decimal("0")) -> None:
        self.name = name
        self.cash = cash
        self._positions: dict[str, Position] = {}
        self._orders: list[Order] = []

    @property
    def positions(self) -> list[Position]:
        return [p for p in self._positions.values() if p.quantity > 0]

    def execute_order(self, order: Order) -> bool:
        """Execute an order against the portfolio."""
        if order.side == OrderSide.BUY:
            cost = order.total_cost
            if cost > self.cash:
                return False
            self.cash -= cost
            pos = self._positions.setdefault(order.symbol, Position(symbol=order.symbol))
            total_cost = pos.avg_cost * pos.quantity + order.price * order.quantity
            pos.quantity += order.quantity
            pos.avg_cost = (total_cost / pos.quantity).quantize(TWO_PLACES) if pos.quantity > 0 else Decimal("0")
        else:
            pos = self._positions.get(order.symbol)
            if pos is None or pos.quantity < order.quantity:
                return False
            self.cash += order.total_cost
            pos.quantity -= order.quantity
            if pos.quantity == 0:
                pos.avg_cost = Decimal("0")

        self._orders.append(order)
        return True

    def total_value(self, prices: dict[str, Decimal]) -> Decimal:
        """Total portfolio value at given prices."""
        total = self.cash
        for pos in self.positions:
            price = prices.get(pos.symbol, Decimal("0"))
            total += pos.market_value(price)
        return total.quantize(TWO_PLACES)

    def total_pnl(self, prices: dict[str, Decimal]) -> Decimal:
        """Total unrealized P&L."""
        pnl = Decimal("0")
        for pos in self.positions:
            price = prices.get(pos.symbol, pos.avg_cost)
            pnl += pos.unrealized_pnl(price)
        return pnl.quantize(TWO_PLACES)


@dataclass
class PriceAlert:
    """A price alert."""

    symbol: str
    condition: AlertCondition
    threshold: Decimal
    triggered: bool = False
    message: str = ""

    def check(self, current_price: Decimal, previous_price: Decimal | None = None) -> bool:
        """Check if alert should trigger."""
        if self.triggered:
            return False
        if self.condition == AlertCondition.ABOVE:
            if current_price >= self.threshold:
                self.triggered = True
                self.message = f"{self.symbol} is above ${self.threshold} (current: ${current_price})"
                return True
        elif self.condition == AlertCondition.BELOW:
            if current_price <= self.threshold:
                self.triggered = True
                self.message = f"{self.symbol} is below ${self.threshold} (current: ${current_price})"
                return True
        elif self.condition == AlertCondition.PERCENT_CHANGE and previous_price:
            if previous_price != 0:
                change = abs((current_price - previous_price) / previous_price * 100)
                if change >= self.threshold:
                    self.triggered = True
                    self.message = f"{self.symbol} moved {change:.2f}% (threshold: {self.threshold}%)"
                    return True
        return False
