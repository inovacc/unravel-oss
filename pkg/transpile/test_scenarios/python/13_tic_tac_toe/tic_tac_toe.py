"""Tic-tac-toe game with AI opponent using minimax.

Covers: 2D lists, recursion (minimax), copy.deepcopy,
        __repr__, Literal type, tuple returns,
        inf/-inf, enumerate with unpacking.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from enum import Enum
from typing import Literal


class Cell(Enum):
    """Board cell states."""

    EMPTY = "."
    X = "X"
    O = "O"

    def __str__(self) -> str:
        return self.value


Player = Literal["X", "O"]
Position = tuple[int, int]

WINNING_LINES: list[list[Position]] = [
    # Rows
    [(0, 0), (0, 1), (0, 2)],
    [(1, 0), (1, 1), (1, 2)],
    [(2, 0), (2, 1), (2, 2)],
    # Columns
    [(0, 0), (1, 0), (2, 0)],
    [(0, 1), (1, 1), (2, 1)],
    [(0, 2), (1, 2), (2, 2)],
    # Diagonals
    [(0, 0), (1, 1), (2, 2)],
    [(0, 2), (1, 1), (2, 0)],
]


@dataclass
class Board:
    """3x3 tic-tac-toe board."""

    grid: list[list[Cell]] = field(default_factory=lambda: [
        [Cell.EMPTY for _ in range(3)] for _ in range(3)
    ])

    def get(self, row: int, col: int) -> Cell:
        return self.grid[row][col]

    def set(self, row: int, col: int, cell: Cell) -> None:
        if self.grid[row][col] != Cell.EMPTY:
            raise ValueError(f"Cell ({row}, {col}) is already occupied")
        self.grid[row][col] = cell

    def is_empty(self, row: int, col: int) -> bool:
        return self.grid[row][col] == Cell.EMPTY

    def available_moves(self) -> list[Position]:
        return [
            (r, c)
            for r in range(3)
            for c in range(3)
            if self.grid[r][c] == Cell.EMPTY
        ]

    def is_full(self) -> bool:
        return all(
            self.grid[r][c] != Cell.EMPTY
            for r in range(3)
            for c in range(3)
        )

    def check_winner(self) -> Cell | None:
        """Check if there's a winner. Returns winning cell or None."""
        for line in WINNING_LINES:
            cells = [self.grid[r][c] for r, c in line]
            if cells[0] != Cell.EMPTY and cells[0] == cells[1] == cells[2]:
                return cells[0]
        return None

    def is_terminal(self) -> bool:
        return self.check_winner() is not None or self.is_full()

    def copy(self) -> Board:
        return Board(grid=copy.deepcopy(self.grid))

    def __repr__(self) -> str:
        rows = []
        for r in range(3):
            rows.append(" | ".join(str(self.grid[r][c]) for c in range(3)))
        separator = "\n---------\n"
        return separator.join(rows)

    def __hash__(self) -> int:
        return hash(tuple(
            self.grid[r][c] for r in range(3) for c in range(3)
        ))


@dataclass
class GameResult:
    """Outcome of a game."""

    winner: Player | None
    is_draw: bool
    moves: list[tuple[Player, Position]]
    board: Board

    @property
    def total_moves(self) -> int:
        return len(self.moves)


class MinimaxAI:
    """AI player using minimax algorithm with alpha-beta pruning."""

    def __init__(self, player: Player) -> None:
        self.player = player
        self.opponent: Player = "O" if player == "X" else "X"
        self._nodes_evaluated = 0

    @property
    def nodes_evaluated(self) -> int:
        return self._nodes_evaluated

    def best_move(self, board: Board) -> Position:
        """Find the best move using minimax."""
        self._nodes_evaluated = 0
        best_score = float("-inf")
        best_pos: Position = (0, 0)

        for row, col in board.available_moves():
            new_board = board.copy()
            new_board.set(row, col, Cell.X if self.player == "X" else Cell.O)
            score = self._minimax(new_board, depth=0, is_maximizing=False,
                                   alpha=float("-inf"), beta=float("inf"))
            if score > best_score:
                best_score = score
                best_pos = (row, col)

        return best_pos

    def _minimax(
        self, board: Board, depth: int, is_maximizing: bool,
        alpha: float, beta: float,
    ) -> float:
        """Minimax with alpha-beta pruning."""
        self._nodes_evaluated += 1

        winner = board.check_winner()
        if winner is not None:
            if winner.value == self.player:
                return 10 - depth
            return depth - 10

        if board.is_full():
            return 0

        if is_maximizing:
            max_eval = float("-inf")
            player_cell = Cell.X if self.player == "X" else Cell.O
            for row, col in board.available_moves():
                new_board = board.copy()
                new_board.set(row, col, player_cell)
                eval_score = self._minimax(new_board, depth + 1, False, alpha, beta)
                max_eval = max(max_eval, eval_score)
                alpha = max(alpha, eval_score)
                if beta <= alpha:
                    break
            return max_eval
        else:
            min_eval = float("inf")
            opp_cell = Cell.X if self.opponent == "X" else Cell.O
            for row, col in board.available_moves():
                new_board = board.copy()
                new_board.set(row, col, opp_cell)
                eval_score = self._minimax(new_board, depth + 1, True, alpha, beta)
                min_eval = min(min_eval, eval_score)
                beta = min(beta, eval_score)
                if beta <= alpha:
                    break
            return min_eval


class Game:
    """Manages a tic-tac-toe game."""

    def __init__(self, player_x: str = "Human", player_o: str = "AI") -> None:
        self.board = Board()
        self.player_x = player_x
        self.player_o = player_o
        self.current_player: Player = "X"
        self.moves: list[tuple[Player, Position]] = []
        self._ai: MinimaxAI | None = None
        if player_o == "AI":
            self._ai = MinimaxAI("O")

    @property
    def current_name(self) -> str:
        return self.player_x if self.current_player == "X" else self.player_o

    def make_move(self, row: int, col: int) -> bool:
        """Make a move. Returns True if valid."""
        if self.board.is_terminal():
            return False
        if not self.board.is_empty(row, col):
            return False

        cell = Cell.X if self.current_player == "X" else Cell.O
        self.board.set(row, col, cell)
        self.moves.append((self.current_player, (row, col)))
        self.current_player = "O" if self.current_player == "X" else "X"
        return True

    def ai_move(self) -> Position | None:
        """Let the AI make a move."""
        if self._ai is None or self.current_player != "O":
            return None
        if self.board.is_terminal():
            return None
        pos = self._ai.best_move(self.board)
        self.make_move(pos[0], pos[1])
        return pos

    def result(self) -> GameResult | None:
        """Get game result if game is over."""
        if not self.board.is_terminal():
            return None
        winner_cell = self.board.check_winner()
        winner: Player | None = None
        if winner_cell == Cell.X:
            winner = "X"
        elif winner_cell == Cell.O:
            winner = "O"
        return GameResult(
            winner=winner,
            is_draw=winner is None,
            moves=self.moves.copy(),
            board=self.board.copy(),
        )


@dataclass
class GameStats:
    """Track statistics across multiple games."""

    x_wins: int = 0
    o_wins: int = 0
    draws: int = 0

    @property
    def total(self) -> int:
        return self.x_wins + self.o_wins + self.draws

    def record(self, result: GameResult) -> None:
        if result.winner == "X":
            self.x_wins += 1
        elif result.winner == "O":
            self.o_wins += 1
        else:
            self.draws += 1

    def win_rate(self, player: Player) -> float:
        if self.total == 0:
            return 0.0
        wins = self.x_wins if player == "X" else self.o_wins
        return wins / self.total * 100

    def format(self) -> str:
        return (
            f"Games: {self.total}\n"
            f"X wins: {self.x_wins} ({self.win_rate('X'):.1f}%)\n"
            f"O wins: {self.o_wins} ({self.win_rate('O'):.1f}%)\n"
            f"Draws: {self.draws}"
        )
