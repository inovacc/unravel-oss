"""A scientific calculator with expression parsing and evaluation.

Demonstrates: functions, classes, type hints, error handling, dicts, enums.
Difficulty: Easy (~120 LOC)
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Callable


class TokenType(Enum):
    NUMBER = auto()
    PLUS = auto()
    MINUS = auto()
    MULTIPLY = auto()
    DIVIDE = auto()
    POWER = auto()
    LPAREN = auto()
    RPAREN = auto()
    FUNC = auto()
    EOF = auto()


@dataclass
class Token:
    type: TokenType
    value: str = ""


class LexerError(Exception):
    pass


class ParseError(Exception):
    pass


FUNCTIONS: dict[str, Callable[[float], float]] = {
    "sin": math.sin,
    "cos": math.cos,
    "tan": math.tan,
    "sqrt": math.sqrt,
    "abs": abs,
    "log": math.log,
    "log10": math.log10,
    "exp": math.exp,
}


def tokenize(expression: str) -> list[Token]:
    """Tokenize a mathematical expression."""
    tokens: list[Token] = []
    i = 0

    while i < len(expression):
        ch = expression[i]

        if ch.isspace():
            i += 1
            continue

        if ch.isdigit() or ch == ".":
            start = i
            has_dot = ch == "."
            i += 1
            while i < len(expression) and (expression[i].isdigit() or (expression[i] == "." and not has_dot)):
                if expression[i] == ".":
                    has_dot = True
                i += 1
            tokens.append(Token(TokenType.NUMBER, expression[start:i]))
            continue

        if ch.isalpha():
            start = i
            while i < len(expression) and expression[i].isalpha():
                i += 1
            name = expression[start:i]
            if name in FUNCTIONS:
                tokens.append(Token(TokenType.FUNC, name))
            else:
                raise LexerError(f"Unknown function: {name}")
            continue

        simple_tokens = {
            "+": TokenType.PLUS,
            "-": TokenType.MINUS,
            "*": TokenType.MULTIPLY,
            "/": TokenType.DIVIDE,
            "^": TokenType.POWER,
            "(": TokenType.LPAREN,
            ")": TokenType.RPAREN,
        }

        if ch in simple_tokens:
            tokens.append(Token(simple_tokens[ch], ch))
            i += 1
            continue

        raise LexerError(f"Unexpected character: {ch}")

    tokens.append(Token(TokenType.EOF))
    return tokens


class Parser:
    """Recursive descent parser for mathematical expressions."""

    def __init__(self, tokens: list[Token]) -> None:
        self._tokens = tokens
        self._pos = 0

    def _current(self) -> Token:
        return self._tokens[self._pos]

    def _consume(self, expected: TokenType) -> Token:
        tok = self._current()
        if tok.type != expected:
            raise ParseError(f"Expected {expected.name}, got {tok.type.name}")
        self._pos += 1
        return tok

    def parse(self) -> float:
        result = self._expression()
        self._consume(TokenType.EOF)
        return result

    def _expression(self) -> float:
        result = self._term()
        while self._current().type in (TokenType.PLUS, TokenType.MINUS):
            op = self._current()
            self._pos += 1
            right = self._term()
            if op.type == TokenType.PLUS:
                result += right
            else:
                result -= right
        return result

    def _term(self) -> float:
        result = self._power()
        while self._current().type in (TokenType.MULTIPLY, TokenType.DIVIDE):
            op = self._current()
            self._pos += 1
            right = self._power()
            if op.type == TokenType.MULTIPLY:
                result *= right
            else:
                if right == 0:
                    raise ParseError("Division by zero")
                result /= right
        return result

    def _power(self) -> float:
        base = self._unary()
        if self._current().type == TokenType.POWER:
            self._pos += 1
            exponent = self._power()  # right-associative
            return base ** exponent
        return base

    def _unary(self) -> float:
        if self._current().type == TokenType.MINUS:
            self._pos += 1
            return -self._atom()
        return self._atom()

    def _atom(self) -> float:
        tok = self._current()

        if tok.type == TokenType.NUMBER:
            self._pos += 1
            return float(tok.value)

        if tok.type == TokenType.FUNC:
            self._pos += 1
            self._consume(TokenType.LPAREN)
            arg = self._expression()
            self._consume(TokenType.RPAREN)
            return FUNCTIONS[tok.value](arg)

        if tok.type == TokenType.LPAREN:
            self._pos += 1
            result = self._expression()
            self._consume(TokenType.RPAREN)
            return result

        raise ParseError(f"Unexpected token: {tok.type.name}")


@dataclass
class Calculator:
    """Calculator with expression history."""

    history: list[tuple[str, float]] = field(default_factory=list)

    def evaluate(self, expression: str) -> float:
        """Evaluate an expression and record it in history."""
        tokens = tokenize(expression)
        parser = Parser(tokens)
        result = parser.parse()
        self.history.append((expression, result))
        return result

    def last_result(self) -> float | None:
        """Return the most recent result, or None if no history."""
        if not self.history:
            return None
        return self.history[-1][1]

    def clear_history(self) -> None:
        """Clear all history."""
        self.history.clear()


def main() -> None:
    calc = Calculator()
    expressions = [
        "2 + 3 * 4",
        "sqrt(16) + 2^3",
        "sin(3.14159 / 2)",
        "(10 - 3) * (2 + 1)",
        "log(exp(5))",
    ]

    for expr in expressions:
        try:
            result = calc.evaluate(expr)
            print(f"{expr} = {result:.6f}")
        except (LexerError, ParseError) as e:
            print(f"Error evaluating '{expr}': {e}")

    print(f"\nTotal evaluations: {len(calc.history)}")
    print(f"Last result: {calc.last_result()}")


if __name__ == "__main__":
    main()
