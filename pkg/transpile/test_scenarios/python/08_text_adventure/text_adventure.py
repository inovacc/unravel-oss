"""Text-based adventure game engine.

Covers: ABC, abstract methods, __repr__/__str__, dict of callables,
        match/case (structural pattern matching), walrus operator,
        nested classes, class hierarchy, tuple unpacking.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Callable


class Direction(Enum):
    """Movement directions."""

    NORTH = auto()
    SOUTH = auto()
    EAST = auto()
    WEST = auto()
    UP = auto()
    DOWN = auto()

    @classmethod
    def from_string(cls, s: str) -> Direction | None:
        """Parse direction from user input."""
        mapping = {
            "n": cls.NORTH, "north": cls.NORTH,
            "s": cls.SOUTH, "south": cls.SOUTH,
            "e": cls.EAST, "east": cls.EAST,
            "w": cls.WEST, "west": cls.WEST,
            "u": cls.UP, "up": cls.UP,
            "d": cls.DOWN, "down": cls.DOWN,
        }
        return mapping.get(s.lower().strip())


@dataclass
class Item:
    """An item that can be picked up and used."""

    name: str
    description: str
    weight: float = 1.0
    usable: bool = True
    hidden: bool = False

    def __str__(self) -> str:
        return f"{self.name}: {self.description}"

    def __repr__(self) -> str:
        return f"Item({self.name!r})"


@dataclass
class Room:
    """A location in the game world."""

    name: str
    description: str
    exits: dict[Direction, str] = field(default_factory=dict)
    items: list[Item] = field(default_factory=list)
    visited: bool = False
    locked: bool = False
    required_item: str | None = None

    def add_exit(self, direction: Direction, room_id: str) -> None:
        """Add an exit to another room."""
        self.exits[direction] = room_id

    def available_exits(self) -> list[Direction]:
        """List available exits."""
        return list(self.exits.keys())

    def visible_items(self) -> list[Item]:
        """List non-hidden items."""
        return [item for item in self.items if not item.hidden]

    def find_item(self, name: str) -> Item | None:
        """Find an item by name (case-insensitive)."""
        for item in self.items:
            if item.name.lower() == name.lower():
                return item
        return None


class Entity(ABC):
    """Base class for game entities."""

    def __init__(self, name: str, health: int = 100) -> None:
        self.name = name
        self.health = health
        self._alive = True

    @property
    def alive(self) -> bool:
        return self._alive and self.health > 0

    @abstractmethod
    def interact(self, player: Player) -> str:
        """Interact with a player."""

    def take_damage(self, amount: int) -> None:
        """Reduce health."""
        self.health = max(0, self.health - amount)
        if self.health == 0:
            self._alive = False


class NPC(Entity):
    """Non-player character with dialogue."""

    def __init__(self, name: str, dialogue: list[str], health: int = 100) -> None:
        super().__init__(name, health)
        self._dialogue = dialogue
        self._dialogue_index = 0

    def interact(self, player: Player) -> str:
        """Get next line of dialogue."""
        if not self._dialogue:
            return f"{self.name} has nothing to say."
        line = self._dialogue[self._dialogue_index % len(self._dialogue)]
        self._dialogue_index += 1
        return f"{self.name}: {line}"


class Enemy(Entity):
    """Hostile entity that can be fought."""

    def __init__(self, name: str, health: int, damage: int, loot: Item | None = None) -> None:
        super().__init__(name, health)
        self.damage = damage
        self.loot = loot

    def interact(self, player: Player) -> str:
        """Attack the player."""
        player.take_damage(self.damage)
        return f"{self.name} attacks for {self.damage} damage!"


@dataclass
class Inventory:
    """Player inventory with weight limit."""

    max_weight: float = 50.0
    items: list[Item] = field(default_factory=list)

    @property
    def current_weight(self) -> float:
        return sum(item.weight for item in self.items)

    @property
    def remaining_capacity(self) -> float:
        return self.max_weight - self.current_weight

    def can_add(self, item: Item) -> bool:
        return self.current_weight + item.weight <= self.max_weight

    def add(self, item: Item) -> bool:
        if not self.can_add(item):
            return False
        self.items.append(item)
        return True

    def remove(self, name: str) -> Item | None:
        for i, item in enumerate(self.items):
            if item.name.lower() == name.lower():
                return self.items.pop(i)
        return None

    def has(self, name: str) -> bool:
        return any(item.name.lower() == name.lower() for item in self.items)

    def __len__(self) -> int:
        return len(self.items)

    def __iter__(self):
        yield from self.items


class Player(Entity):
    """The player character."""

    def __init__(self, name: str) -> None:
        super().__init__(name, health=100)
        self.inventory = Inventory()
        self.score: int = 0
        self.moves: int = 0

    def interact(self, player: Player) -> str:
        return "You talk to yourself."

    def take_damage(self, amount: int) -> None:
        super().take_damage(amount)

    def heal(self, amount: int) -> None:
        self.health = min(100, self.health + amount)

    def pickup(self, item: Item) -> bool:
        return self.inventory.add(item)


class GameWorld:
    """The game world containing rooms and entities."""

    def __init__(self) -> None:
        self.rooms: dict[str, Room] = {}
        self.entities: dict[str, list[Entity]] = {}

    def add_room(self, room_id: str, room: Room) -> None:
        self.rooms[room_id] = room

    def add_entity(self, room_id: str, entity: Entity) -> None:
        self.entities.setdefault(room_id, []).append(entity)

    def get_room(self, room_id: str) -> Room | None:
        return self.rooms.get(room_id)

    def get_entities(self, room_id: str) -> list[Entity]:
        return self.entities.get(room_id, [])

    def connect_rooms(
        self, room_a: str, direction: Direction, room_b: str, bidirectional: bool = True
    ) -> None:
        """Connect two rooms with exits."""
        opposites = {
            Direction.NORTH: Direction.SOUTH,
            Direction.SOUTH: Direction.NORTH,
            Direction.EAST: Direction.WEST,
            Direction.WEST: Direction.EAST,
            Direction.UP: Direction.DOWN,
            Direction.DOWN: Direction.UP,
        }
        self.rooms[room_a].add_exit(direction, room_b)
        if bidirectional:
            self.rooms[room_b].add_exit(opposites[direction], room_a)


@dataclass
class GameState:
    """Serializable game state."""

    player_name: str
    player_health: int
    current_room: str
    score: int
    moves: int
    inventory_items: list[str]
    visited_rooms: list[str]

    def to_json(self) -> str:
        return json.dumps({
            "player_name": self.player_name,
            "player_health": self.player_health,
            "current_room": self.current_room,
            "score": self.score,
            "moves": self.moves,
            "inventory_items": self.inventory_items,
            "visited_rooms": self.visited_rooms,
        }, indent=2)

    @classmethod
    def from_json(cls, data: str) -> GameState:
        d = json.loads(data)
        return cls(**d)


CommandHandler = Callable[[str], str]


class GameEngine:
    """Main game engine that processes commands."""

    def __init__(self, world: GameWorld, player: Player, start_room: str) -> None:
        self.world = world
        self.player = player
        self.current_room_id = start_room
        self._commands: dict[str, CommandHandler] = {
            "look": self._cmd_look,
            "go": self._cmd_go,
            "take": self._cmd_take,
            "drop": self._cmd_drop,
            "inventory": self._cmd_inventory,
            "talk": self._cmd_talk,
            "status": self._cmd_status,
        }

    @property
    def current_room(self) -> Room:
        room = self.world.get_room(self.current_room_id)
        assert room is not None
        return room

    def process_command(self, raw_input: str) -> str:
        """Parse and execute a command."""
        parts = raw_input.strip().split(maxsplit=1)
        if not parts:
            return "What do you want to do?"

        command = parts[0].lower()
        argument = parts[1] if len(parts) > 1 else ""

        handler = self._commands.get(command)
        if handler is None:
            return f"Unknown command: {command}"

        self.player.moves += 1
        return handler(argument)

    def _cmd_look(self, _arg: str) -> str:
        room = self.current_room
        lines = [room.name, room.description, ""]
        if items := room.visible_items():
            lines.append("Items: " + ", ".join(i.name for i in items))
        exits = room.available_exits()
        lines.append("Exits: " + ", ".join(d.name.lower() for d in exits))
        return "\n".join(lines)

    def _cmd_go(self, arg: str) -> str:
        direction = Direction.from_string(arg)
        if direction is None:
            return f"Unknown direction: {arg}"
        room = self.current_room
        if direction not in room.exits:
            return "You can't go that way."
        target_id = room.exits[direction]
        target = self.world.get_room(target_id)
        if target is None:
            return "That room doesn't exist."
        if target.locked:
            if target.required_item and self.player.inventory.has(target.required_item):
                target.locked = False
            else:
                return f"The way is locked. You need: {target.required_item}"
        self.current_room_id = target_id
        target.visited = True
        return self._cmd_look("")

    def _cmd_take(self, arg: str) -> str:
        if not arg:
            return "Take what?"
        room = self.current_room
        if (item := room.find_item(arg)) is None:
            return f"No '{arg}' here."
        if not self.player.pickup(item):
            return "Inventory full!"
        room.items.remove(item)
        self.player.score += 10
        return f"Picked up {item.name}."

    def _cmd_drop(self, arg: str) -> str:
        if not arg:
            return "Drop what?"
        if (item := self.player.inventory.remove(arg)) is None:
            return f"You don't have '{arg}'."
        self.current_room.items.append(item)
        return f"Dropped {item.name}."

    def _cmd_inventory(self, _arg: str) -> str:
        inv = self.player.inventory
        if not inv.items:
            return "Inventory is empty."
        lines = ["Inventory:"]
        lines.extend(f"  - {item}" for item in inv)
        lines.append(f"Weight: {inv.current_weight:.1f}/{inv.max_weight:.1f}")
        return "\n".join(lines)

    def _cmd_talk(self, arg: str) -> str:
        entities = self.world.get_entities(self.current_room_id)
        for entity in entities:
            if entity.name.lower() == arg.lower() and isinstance(entity, NPC):
                return entity.interact(self.player)
        return f"No one named '{arg}' is here."

    def _cmd_status(self, _arg: str) -> str:
        p = self.player
        return (
            f"Name: {p.name}\n"
            f"Health: {p.health}/100\n"
            f"Score: {p.score}\n"
            f"Moves: {p.moves}"
        )

    def save_state(self) -> GameState:
        """Save current game state."""
        return GameState(
            player_name=self.player.name,
            player_health=self.player.health,
            current_room=self.current_room_id,
            score=self.player.score,
            moves=self.player.moves,
            inventory_items=[i.name for i in self.player.inventory],
            visited_rooms=[
                rid for rid, room in self.world.rooms.items() if room.visited
            ],
        )
