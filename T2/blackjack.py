import socket
import threading
import time
import json
import random
import sys
import logging
import colorama
from colorama import Fore, Style
import os

# Configure logging to record messages in an external file
logging.basicConfig(
    filename='blackjack_debug.log',
    filemode='a',
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.DEBUG
)

# Initialize colorama
colorama.init(autoreset=True)

# Configuration for the machines (using localhost and different ports)
MACHINES = [
    ('127.0.0.1', 5001),
    ('127.0.0.1', 5002),
    ('127.0.0.1', 5003),
    ('127.0.0.1', 5004)
]

class BlackjackGame:
    def __init__(self, machine_index):
        self.machine_index = machine_index
        self.current_machine = MACHINES[self.machine_index]
        self.next_machine = MACHINES[(self.machine_index + 1) % len(MACHINES)]
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(self.current_machine)
        self.sock.settimeout(5.0)  # Timeout to prevent blocking on receive

        self.game_state = {
            'players': [],  # List of players with their cards and status
            'dealer': [],
            'deck': [],
            'current_player': 0,  # Index of the current player
            'status': 'waiting'  # 'waiting', 'active', 'finished'
        }

        logging.info(f"Machine {self.machine_index} started on port {self.current_machine[1]}.")
        self.message_cache = set()  # Track seen messages to ensure full ring traversal
        self.is_token_holder = False
        self.game_started = False

    def initialize_deck(self):
        suits = ['Hearts', 'Diamonds', 'Clubs', 'Spades']
        ranks = ['2', '3', '4', '5', '6', '7', '8', '9', '10', 'J', 'Q', 'K', 'A']
        deck = [{'suit': suit, 'rank': rank} for suit in suits for rank in ranks]
        random.shuffle(deck)
        logging.debug("Deck initialized and shuffled.")
        return deck

    def calculate_hand(self, hand):
        value = 0
        aces = 0
        for card in hand:
            rank = card['rank']
            if rank in ['J', 'Q', 'K']:
                value += 10
            elif rank == 'A':
                aces += 1
                value += 11
            else:
                value += int(rank)
        while value > 21 and aces:
            value -= 10
            aces -= 1
        return value

    def broadcast_message(self, message):
        if 'id' not in message:
            message['id'] = f"{self.machine_index}-{time.time()}"
        if message['id'] not in self.message_cache:
            self.message_cache.add(message['id'])
            serialized = json.dumps(message).encode('utf-8')
            self.sock.sendto(serialized, self.next_machine)
            logging.debug(f"Sent message to {self.next_machine}: {message}")

    def listen(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(4096)
                message = json.loads(data.decode('utf-8'))
                
                # Check if message has completed the ring
                if message.get('id') in self.message_cache:
                    if message.get('type') == 'TOKEN':
                        self.is_token_holder = True
                        self.handle_token()
                    continue
                
                self.handle_message(message)
                self.broadcast_message(message)
                
            except socket.timeout:
                continue

    def handle_message(self, msg):
        msg_type = msg.get('type')
        if msg_type == 'GAME_START':
            self.handle_game_start(msg)
        elif msg_type == 'PLAYER_ACTION':
            self.handle_player_action(msg)
        elif msg_type == 'GAME_STATE':
            self.handle_game_state(msg)
        elif msg_type == 'TOKEN':
            self.handle_token()
        elif msg_type == 'READY_FOR_RESULTS':
            self.handle_ready_for_results(msg)
        elif msg_type == 'GAME_FINISHED':
            self.handle_game_finished(msg)

    def handle_token(self):
        if not self.game_started and self.machine_index == 0:
            self.start_game()
        elif self.game_state['status'] == 'active':
            self.process_current_player()
        
        # Release token after processing
        time.sleep(1)  # Small delay to prevent token racing
        self.is_token_holder = False
        self.broadcast_message({'type': 'TOKEN'})

    def start_game(self):
        self.game_started = True
        self.broadcast_message({
            'type': 'GAME_START',
            'state': self.game_state,
            'initiator': self.machine_index
        })

    def process_current_player(self):
        if self.game_state['current_player'] == self.machine_index:
            self.broadcast_message({
                'type': 'GAME_STATE',
                'state': self.game_state,
                'current_player': self.game_state['current_player']
            })

    def process_player_action(self, player_index, action):
        player = self.game_state['players'][player_index]

        # Check if player is busted or not active
        if player['status'] in ['busted', 'done', 'surrendered']:
            logging.warning(f"Player {player_index} is not active for actions (status: {player['status']}).")
            return

        act = action.get('action')

        print(f"\n[Machine {self.machine_index}] Player {player_index} chose {act}.")
        logging.info(f"Player {player_index} chose {act}.")

        if act == 'HIT':
            self.hit(player_index)
        elif act == 'STAND':
            self.stand(player_index)
            return  # Return immediately after standing to prevent additional actions
        elif act == 'DOUBLE':
            self.double(player_index)
        elif act == 'SURRENDER':
            self.surrender(player_index)
        else:
            logging.error(f"Unknown action: {act}")

    def hit(self, player_index):
        player = self.game_state['players'][player_index]
        if not self.game_state['deck']:
            print("[Deck] Deck is empty. Reinitializing the deck.")
            logging.warning("Deck empty. Reinitializing.")
            self.game_state['deck'] = self.initialize_deck()
        card = self.game_state['deck'].pop()
        player['cards'].append(card)
        value = self.calculate_hand(player['cards'])
        print(f"[Machine {self.machine_index}] Player {player_index} received {card['rank']} of {card['suit']}. Hand value: {value}")
        logging.info(f"Player {player_index} received {card['rank']} of {card['suit']}. Hand value: {value}")
        if value > 21:
            player['status'] = 'busted'
            print(f"[Machine {self.machine_index}] Player {player_index} busted!")
            logging.info(f"Player {player_index} busted!")

    def stand(self, player_index):
        player = self.game_state['players'][player_index]
        player['status'] = 'done'
        print(f"[Machine {self.machine_index}] Player {player_index} decided to STAND.")
        logging.info(f"Player {player_index} decided to STAND.")
        # Move to next player after standing
        self.game_state['current_player'] = (player_index + 1) % len(MACHINES)
        self.broadcast_message({'type': 'GAME_STATE', 'state': self.game_state})

    def double(self, player_index):
        player = self.game_state['players'][player_index]
        if not player['can_double']:
            print(f"[Machine {self.machine_index}] Player {player_index} cannot DOUBLE.")
            logging.warning(f"Player {player_index} attempted to DOUBLE but cannot.")
            return
        if not self.game_state['deck']:
            print("[Deck] Deck is empty. Reinitializing the deck.")
            logging.warning("Deck empty. Reinitializing.")
            self.game_state['deck'] = self.initialize_deck()
        card = self.game_state['deck'].pop()
        player['cards'].append(card)
        player['can_double'] = False
        value = self.calculate_hand(player['cards'])
        print(f"[Machine {self.machine_index}] Player {player_index} doubled and received {card['rank']} of {card['suit']}. Hand value: {value}")
        logging.info(f"Player {player_index} doubled and received {card['rank']} of {card['suit']}. Hand value: {value}")
        if value > 21:
            player['status'] = 'busted'
            print(f"[Machine {self.machine_index}] Player {player_index} busted after doubling!")
            logging.info(f"Player {player_index} busted after doubling!")
        else:
            player['status'] = 'done'
            print(f"[Machine {self.machine_index}] Player {player_index} is now in STAND.")
            logging.info(f"Player {player_index} is now in STAND.")

    def surrender(self, player_index):
        player = self.game_state['players'][player_index]
        if not player['can_surrender']:
            print(f"[Machine {self.machine_index}] Player {player_index} cannot SURRENDER.")
            logging.warning(f"Player {player_index} attempted to SURRENDER but cannot.")
            return
        player['status'] = 'surrendered'
        print(f"[Machine {self.machine_index}] Player {player_index} surrendered.")
        logging.info(f"Player {player_index} surrendered.")

    def display_game_state(self):
        # Helper function to format cards
        def format_card(card):
            suit_symbols = {
                'Hearts': '♥',
                'Diamonds': '♦',
                'Clubs': '♣',
                'Spades': '♠'
            }
            suit_colors = {
                'Hearts': Fore.RED,
                'Diamonds': Fore.RED,
                'Clubs': Fore.GREEN,
                'Spades': Fore.BLUE
            }
            rank = card['rank']
            suit = card['suit']
            symbol = suit_symbols.get(suit, '?')
            color = suit_colors.get(suit, Fore.WHITE)
            return f"{color}{rank}{symbol}{Style.RESET_ALL}"

        print("\n" + "=" * 40)
        print(Fore.YELLOW + Style.BRIGHT + "          Current Game State          " + Style.RESET_ALL)
        print("=" * 40)
        print(Fore.MAGENTA + Style.BRIGHT + "Dealer:")
        dealer_hand = '  '.join([format_card(card) for card in self.game_state['dealer']])
        dealer_value = self.calculate_hand(self.game_state['dealer'])
        print(f"  Hand: {dealer_hand}   |  Value: {dealer_value}")

        print(Fore.CYAN + Style.BRIGHT + "\nPlayers:")
        for idx, player in enumerate(self.game_state['players']):
            print(f"  {Fore.CYAN}Player {idx}:{Style.RESET_ALL}")
            hand_cards = '  '.join([format_card(card) for card in player['cards']])
            value = self.calculate_hand(player['cards'])
            status = player['status'].capitalize()
            print(f"    Hand: {hand_cards}   |  Value: {value}   |  Status: {status}")
            print(f"    Player Status: {player['status'].capitalize()}")
        print("=" * 40 + "\n")

    def handle_token(self):
        if not self.game_started and self.machine_index == 0:
            self.start_game()
        elif self.game_state['status'] == 'active':
            self.process_current_player()
        
        # Release token after processing
        time.sleep(1)  # Small delay to prevent token racing
        self.is_token_holder = False
        self.broadcast_message({'type': 'TOKEN'})

    def start_game(self):
        self.game_started = True
        self.game_state['deck'] = self.initialize_deck()
        self.game_state['players'] = [{
            'cards': [],
            'status': 'active',  # 'active', 'done', 'busted', 'surrendered'
            'can_double': True,
            'can_surrender': True
        } for _ in MACHINES]

        self.game_state['dealer'] = []
        self.game_state['current_player'] = 0
        self.game_state['status'] = 'active'

        # Distribute two cards to each player and the dealer
        for _ in range(2):
            for player in self.game_state['players']:
                if not self.game_state['deck']:
                    self.game_state['deck'] = self.initialize_deck()
                card = self.game_state['deck'].pop()
                player['cards'].append(card)
            if not self.game_state['deck']:
                self.game_state['deck'] = self.initialize_deck()
            dealer_card = self.game_state['deck'].pop()
            self.game_state['dealer'].append(dealer_card)

        # Broadcast the initial game state
        self.broadcast_message({
            'type': 'GAME_START',
            'state': self.game_state,
            'initiator': self.machine_index
        })
        self.display_game_state()
        logging.info("Game started and cards distributed.")

    def process_current_player(self):
        if self.game_state['current_player'] == self.machine_index:
            os.system('cls' if os.name == 'nt' else 'clear')
            self.display_game_state()
            player = self.game_state['players'][self.game_state['current_player']]
            
            # Check if player is busted or not active before allowing actions
            if player['status'] == 'active':
                print(f"\n{Fore.GREEN}=== Your Turn, Player {self.game_state['current_player']} ==={Style.RESET_ALL}")
                hand_cards = '  '.join([self.format_card(card) for card in player['cards']])
                hand_value = self.calculate_hand(player['cards'])
                print(f"Hand: {hand_cards}   |  Value: {hand_value}")
                sys.stdout.flush()
                
                # Get and process player action
                action = self.get_player_action(player)
                self.broadcast_message({'type': 'PLAYER_ACTION', 'player': self.game_state['current_player'], 'action': {'action': action}})
                self.process_player_action(self.game_state['current_player'], {'action': action})
                
                # Check if player is still active after their action
                if self.game_state['players'][self.game_state['current_player']]['status'] != 'active':
                    # Player turn is complete, move to next player
                    self.game_state['current_player'] = (self.game_state['current_player'] + 1) % len(self.game_state['players'])
                    self.broadcast_message({'type': 'GAME_STATE', 'state': self.game_state})
                
                time.sleep(1)
                os.system('cls' if os.name == 'nt' else 'clear')
                self.display_game_state()
            else:
                # Player is not active, move to next player
                print(f"[Machine {self.machine_index}] You cannot play anymore (status: {player['status']}). Moving to the next player.")
                logging.info(f"Player {self.game_state['current_player']} cannot play anymore (status: {player['status']}).")
                self.game_state['current_player'] = (self.game_state['current_player'] + 1) % len(self.game_state['players'])
                self.broadcast_message({'type': 'GAME_STATE', 'state': self.game_state})

        # Check if all players are done
        all_done = all(player['status'] != 'active' for player in self.game_state['players'])
        if all_done and self.game_state['status'] != 'finished':
            self.dealer_play()

    def dealer_play(self):
        self.game_state['status'] = 'finished'
        print("\n" + Fore.MAGENTA + "=== Dealer's Turn ===" + Style.RESET_ALL)
        logging.info("Dealer starts playing.")
        time.sleep(1)  # Delay before dealer starts

        while self.calculate_hand(self.game_state['dealer']) < 17:
            if not self.game_state['deck']:
                print("[Dealer] Deck is empty. Reinitializing the deck.")
                logging.warning("Deck empty during the game. Reinitializing.")
                self.game_state['deck'] = self.initialize_deck()
            card = self.game_state['deck'].pop()
            self.game_state['dealer'].append(card)
            dealer_hand = '  '.join([self.format_card(c) for c in self.game_state['dealer']])
            print(f"[Dealer] Dealer received {self.format_card(card)}. Hand value: {self.calculate_hand(self.game_state['dealer'])}")
            logging.info(f"Dealer received {card['rank']} of {card['suit']}. Hand value: {self.calculate_hand(self.game_state['dealer'])}")
            time.sleep(1)  # Delay between dealer's actions

        dealer_value = self.calculate_hand(self.game_state['dealer'])
        print(f"{Fore.MAGENTA}[Dealer] Final hand value: {dealer_value}{Style.RESET_ALL}")
        logging.info(f"Dealer finished with value: {dealer_value}")

        # Determine results for each player
        for idx, player in enumerate(self.game_state['players']):
            player_value = self.calculate_hand(player['cards'])
            print(f"\n{Fore.CYAN}--- Result for Player {idx} ---{Style.RESET_ALL}")
            player_hand = '  '.join([self.format_card(card) for card in player['cards']])
            dealer_hand = '  '.join([self.format_card(card) for card in self.game_state['dealer']])
            print(f"Your hand: {player_hand}   |  Value: {player_value}")
            print(f"Dealer's hand: {dealer_hand}   |  Value: {dealer_value}")
            logging.info(f"Result for Player {idx}: {player_value} vs Dealer {dealer_value}")

            if player['status'] == 'surrendered':
                print(f"{Fore.YELLOW}Result: You surrendered. Lost half your bet.{Style.RESET_ALL}")
                logging.info("Player surrendered.")
            elif player['status'] == 'busted':
                print(f"{Fore.RED}Result: You busted. Lost your bet.{Style.RESET_ALL}")
                logging.info("Player busted.")
            else:
                if dealer_value > 21:
                    print(f"{Fore.GREEN}Result: Dealer busted. You win!{Style.RESET_ALL}")
                    logging.info("Dealer busted. Player wins.")
                elif player_value > dealer_value:
                    print(f"{Fore.GREEN}Result: You have a higher value. You win!{Style.RESET_ALL}")
                    logging.info("Player has a higher value. Wins.")
                elif player_value < dealer_value:
                    print(f"{Fore.RED}Result: Dealer has a higher value. You lose.{Style.RESET_ALL}")
                    logging.info("Dealer has a higher value. Player loses.")
                else:
                    print(f"{Fore.YELLOW}Result: Push (Tie).{Style.RESET_ALL}")
                    logging.info("Push between Player and Dealer.")

        print(f"\n{Fore.BLUE}=== Game Over ===\n{Style.RESET_ALL}")
        logging.info("Game over.")

        # Wait for all players before showing results
        self.waiting_for_results = True
        if self.machine_index == 0:
            self.broadcast_message({
                'type': 'READY_FOR_RESULTS',
                'state': self.game_state,
                'players_ready': [False] * len(MACHINES)
            })

    def handle_ready_for_results(self, msg):
        players_ready = msg['players_ready']
        if not players_ready[self.machine_index]:
            players_ready[self.machine_index] = True
            self.broadcast_message({
                'type': 'READY_FOR_RESULTS',
                'state': self.game_state,
                'players_ready': players_ready
            })
        
        if all(players_ready):
            self.game_state = msg['state']
            self.display_final_results()
            # Signal game end to all players
            self.broadcast_message({'type': 'GAME_FINISHED', 'state': self.game_state})

    def display_final_results(self):
        dealer_value = self.calculate_hand(self.game_state['dealer'])
        print(f"\n{Fore.BLUE}=== Final Game Results ==={Style.RESET_ALL}")
        logging.info("Displaying final game results.")

        # Display dealer's hand
        dealer_hand = '  '.join([self.format_card(card) for card in self.game_state['dealer']])
        print(f"{Fore.MAGENTA}Dealer's Hand: {dealer_hand}   |  Value: {dealer_value}{Style.RESET_ALL}")

        # Display results for each player
        for idx, player in enumerate(self.game_state['players']):
            player_value = self.calculate_hand(player['cards'])
            print(f"\n{Fore.CYAN}--- Result for Player {idx} ---{Style.RESET_ALL}")
            player_hand = '  '.join([self.format_card(card) for card in player['cards']])
            print(f"Your Hand: {player_hand}   |  Value: {player_value}")
            logging.info(f"Result for Player {idx}: {player_value} vs Dealer {dealer_value}")

            # Determine the outcome
            if player['status'] == 'surrendered':
                print(f"{Fore.YELLOW}Result: You surrendered. Lost half your bet.{Style.RESET_ALL}")
                logging.info("Player surrendered.")
            elif player['status'] == 'busted':
                print(f"{Fore.RED}Result: You busted. Lost your bet.{Style.RESET_ALL}")
                logging.info("Player busted.")
            else:
                if dealer_value > 21:
                    print(f"{Fore.GREEN}Result: Dealer busted. You win!{Style.RESET_ALL}")
                    logging.info("Dealer busted. Player wins.")
                elif player_value > dealer_value:
                    print(f"{Fore.GREEN}Result: You have a higher value. You win!{Style.RESET_ALL}")
                    logging.info("Player has a higher value. Wins.")
                elif player_value < dealer_value:
                    print(f"{Fore.RED}Result: Dealer has a higher value. You lose.{Style.RESET_ALL}")
                    logging.info("Dealer has a higher value. Player loses.")
                else:
                    print(f"{Fore.YELLOW}Result: Push (Tie).{Style.RESET_ALL}")
                    logging.info("Push between Player and Dealer.")

        print(f"\n{Fore.BLUE}=== Game Over ===\n{Style.RESET_ALL}")
        logging.info("Game over.")

    def handle_game_finished(self, msg):
        self.game_state = msg['state']
        logging.info("Game finished message received.")
        self.display_final_results()

    def get_player_action(self, player):
        valid_actions = ['STAND', 'HIT']
        if player['can_double']:
            valid_actions.append('DOUBLE')
        if player['can_surrender'] and len(player['cards']) == 2:
            valid_actions.append('SURRENDER')

        while True:
            print(f"Available actions: {', '.join(valid_actions)}")
            sys.stdout.flush()
            action = input("Choose your action: ").strip().upper()
            if action in valid_actions:
                return action
            else:
                print("Invalid action. Please try again.")
                logging.warning(f"Player attempted an invalid action: {action}")

    def format_card(self, card):
        suit_symbols = {
            'Hearts': '♥',
            'Diamonds': '♦',
            'Clubs': '♣',
            'Spades': '♠'
        }
        suit_colors = {
            'Hearts': Fore.RED,
            'Diamonds': Fore.RED,
            'Clubs': Fore.GREEN,
            'Spades': Fore.BLUE
        }
        rank = card['rank']
        suit = card['suit']
        symbol = suit_symbols.get(suit, '?')
        color = suit_colors.get(suit, Fore.WHITE)
        return f"{color}{rank}{symbol}{Style.RESET_ALL}"

    def run(self):
        listener_thread = threading.Thread(target=self.listen, daemon=True)
        listener_thread.start()

        if self.machine_index == 0:
            time.sleep(2)
            self.is_token_holder = True
            self.handle_token()

        try:
            while True:
                time.sleep(0.1)
        except KeyboardInterrupt:
            self.sock.close()
            sys.exit(0)

    def handle_game_start(self, msg):
        self.game_state = msg['state']
        self.game_started = True
        logging.info("Game started from network message")
        self.display_game_state()

    def handle_player_action(self, msg):
        player_index = msg['player']
        action = msg['action']
        self.process_player_action(player_index, action)
        logging.info(f"Processed player {player_index}'s action: {action}")

    def handle_game_state(self, msg):
        self.game_state = msg['state']
        logging.info("Updated game state from network")
        self.display_game_state()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python blackjack_ring.py <machine_index>")
        sys.exit(1)
    try:
        machine_index = int(sys.argv[1])
        if not 0 <= machine_index < len(MACHINES):
            raise ValueError
    except ValueError:
        print(f"<machine_index> must be a number between 0 and {len(MACHINES)-1}")
        sys.exit(1)
    game = BlackjackGame(machine_index)
    game.run()
