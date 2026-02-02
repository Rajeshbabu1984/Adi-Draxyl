import random
import os

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

class Player:
    def __init__(self, name):
        self.name = name
        self.health = 100
        self.inventory = []
        self.position = "entrance"
    
    def take_damage(self, damage):
        self.health -= damage
        if self.health < 0:
            self.health = 0

class Dungeon:
    def __init__(self):
        self.rooms = {
            "entrance": {"description": "A dark entrance to the dungeon", "exits": ["corridor"]},
            "corridor": {"description": "A long, damp corridor", "exits": ["entrance", "chamber"]},
            "chamber": {"description": "A large chamber with torches on the walls", "exits": ["corridor", "treasure_room"]},
            "treasure_room": {"description": "A room filled with ancient treasures", "exits": ["chamber"]}
        }
    
    def describe_room(self, room):
        return self.rooms[room]["description"]
    
    def get_exits(self, room):
        return self.rooms[room]["exits"]

def main():
    print("=== DUNGEON ADVENTURE ===")
    name = input("Enter your name: ")
    player = Player(name)
    dungeon = Dungeon()
    
    print(f"\nWelcome, {player.name}! You find yourself trapped in a dungeon.")
    
    while player.health > 0:
        print(f"\n--- {player.position.upper().replace('_', ' ')} ---")
        print(dungeon.describe_room(player.position))
        print(f"Health: {player.health}")
        print(f"Available exits: {', '.join(dungeon.get_exits(player.position))}")
        
        if player.position == "treasure_room":
            print("\n🎉 You found the treasure! You escaped the dungeon!")
            break
        
        action = input("\nWhat do you want to do? (move/quit): ").lower()
        
        if action == "quit":
            print("Thanks for playing!")
            break
        elif action == "move":
            destination = input("Where do you want to go? ").lower()
            if destination in dungeon.get_exits(player.position):
                player.position = destination
                
                # Random encounter
                if random.random() < 0.3:
                    damage = random.randint(5, 15)
                    print(f"\n⚠️ A monster attacks! You take {damage} damage.")
                    player.take_damage(damage)
            else:
                print("You can't go that way!")
        else:
            print("Invalid action!")
    
    if player.health <= 0:
        print(f"\n💀 {player.name} has perished in the dungeon...")

if __name__ == "__main__":
    while True:
        clear_screen()
        main()
        play_again = input("\nDo you want to play again? (yes/no): ").lower()
        if play_again != "yes" and play_again != "y":
            print("Thanks for playing! Goodbye!")
            break