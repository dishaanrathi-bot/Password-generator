import sqlite3
import secrets
import string
from datetime import datetime
from getpass import getpass

class DatabaseManager:
    """Create the database and perform low-level SQL operations."""

    def __init__(self, database_name='passwords.db'):
        self.database_name = database_name
        self.connection = sqlite3.connect(self.database_name)
        self.connection.row_factory = sqlite3.Row
        self.create_tables()

    def create_tables(self):
        """Create tables if they do not already exist."""
        query = '\n        CREATE TABLE IF NOT EXISTS password_records (\n            record_id INTEGER PRIMARY KEY AUTOINCREMENT,\n            website TEXT NOT NULL,\n            username TEXT NOT NULL,\n            password TEXT NOT NULL,\n            password_length INTEGER NOT NULL,\n            includes_uppercase INTEGER NOT NULL,\n            includes_lowercase INTEGER NOT NULL,\n            includes_digits INTEGER NOT NULL,\n            includes_symbols INTEGER NOT NULL,\n            created_at TEXT NOT NULL\n        )\n        '
        self.connection.execute(query)
        self.connection.commit()
        history_query = '\n        CREATE TABLE IF NOT EXISTS activity_history (\n            history_id INTEGER PRIMARY KEY AUTOINCREMENT,\n            action TEXT NOT NULL,\n            details TEXT NOT NULL,\n            action_time TEXT NOT NULL\n        )\n        '
        self.connection.execute(history_query)
        self.connection.commit()

    def execute(self, query, values=()):
        """Run an SQL statement and return its cursor."""
        cursor = self.connection.cursor()
        cursor.execute(query, values)
        self.connection.commit()
        return cursor

    def fetch_all(self, query, values=()):
        """Return all rows matching a query."""
        cursor = self.connection.cursor()
        cursor.execute(query, values)
        return cursor.fetchall()

    def fetch_one(self, query, values=()):
        """Return one row matching a query."""
        cursor = self.connection.cursor()
        cursor.execute(query, values)
        return cursor.fetchone()

    def log_action(self, action, details):
        """Save a simple activity record."""
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.execute('INSERT INTO activity_history (action, details, action_time) VALUES (?, ?, ?)', (action, details, now))

    def close(self):
        """Close the database connection."""
        self.connection.close()

class PasswordRecord:
    """Represent one saved password record."""

    def __init__(self, website, username, password, password_length, uppercase=True, lowercase=True, digits=True, symbols=True, record_id=None, created_at=None):
        self._record_id = record_id
        self._website = website.strip()
        self._username = username.strip()
        self._password = password
        self._password_length = int(password_length)
        self._uppercase = bool(uppercase)
        self._lowercase = bool(lowercase)
        self._digits = bool(digits)
        self._symbols = bool(symbols)
        self._created_at = created_at or datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    @property
    def record_id(self):
        return self._record_id

    @property
    def website(self):
        return self._website

    @property
    def username(self):
        return self._username

    @property
    def password(self):
        return self._password

    @property
    def password_length(self):
        return self._password_length

    @property
    def created_at(self):
        return self._created_at

    def to_database_tuple(self):
        """Convert this object into values for an SQL INSERT."""
        return (self._website, self._username, self._password, self._password_length, int(self._uppercase), int(self._lowercase), int(self._digits), int(self._symbols), self._created_at)

    @classmethod
    def from_database_row(cls, row):
        """Build an object from an SQLite row."""
        return cls(website=row['website'], username=row['username'], password=row['password'], password_length=row['password_length'], uppercase=row['includes_uppercase'], lowercase=row['includes_lowercase'], digits=row['includes_digits'], symbols=row['includes_symbols'], record_id=row['record_id'], created_at=row['created_at'])

    def summary(self):
        """Return a safe summary without displaying the password."""
        return f'ID: {self._record_id} | Website: {self._website} | Username: {self._username} | Length: {self._password_length} | Created: {self._created_at}'

    def __str__(self):
        return self.summary()

class StrongPasswordRecord(PasswordRecord):
    """Example of inheritance: a record intended for a strong password."""

    def strength_label(self):
        if self.password_length >= 16:
            return 'Strong-length password'
        if self.password_length >= 12:
            return 'Good-length password'
        return 'Short password; consider using 12 or more characters'

class PasswordGenerator:
    """Generate random passwords using Python's secrets module."""

    def __init__(self):
        self.uppercase_chars = string.ascii_uppercase
        self.lowercase_chars = string.ascii_lowercase
        self.digit_chars = string.digits
        self.symbol_chars = '!@#$%^&*()-_=+[]{};:,.?/'

    def build_character_pool(self, uppercase=True, lowercase=True, digits=True, symbols=True):
        """Combine the character groups selected by the user."""
        pool = ''
        if uppercase:
            pool += self.uppercase_chars
        if lowercase:
            pool += self.lowercase_chars
        if digits:
            pool += self.digit_chars
        if symbols:
            pool += self.symbol_chars
        return pool

    def generate(self, length=16, uppercase=True, lowercase=True, digits=True, symbols=True):
        """Generate a password, ensuring each selected group is represented."""
        if length < 4:
            raise ValueError('Password length must be at least 4.')
        pool = self.build_character_pool(uppercase, lowercase, digits, symbols)
        if not pool:
            raise ValueError('Select at least one character group.')
        groups = []
        if uppercase:
            groups.append(self.uppercase_chars)
        if lowercase:
            groups.append(self.lowercase_chars)
        if digits:
            groups.append(self.digit_chars)
        if symbols:
            groups.append(self.symbol_chars)
        if length < len(groups):
            raise ValueError('Password length is too short for all selected groups.')
        password_chars = [secrets.choice(group) for group in groups]
        while len(password_chars) < length:
            password_chars.append(secrets.choice(pool))
        secrets.SystemRandom().shuffle(password_chars)
        return ''.join(password_chars)

    def estimate_strength(self, password):
        """Give a simple educational strength estimate."""
        score = 0
        if len(password) >= 8:
            score += 1
        if len(password) >= 12:
            score += 1
        if len(password) >= 16:
            score += 1
        if any((char.islower() for char in password)):
            score += 1
        if any((char.isupper() for char in password)):
            score += 1
        if any((char.isdigit() for char in password)):
            score += 1
        if any((not char.isalnum() for char in password)):
            score += 1
        if score <= 3:
            return 'Weak'
        if score <= 5:
            return 'Moderate'
        return 'Strong'

class PasswordService:
    """Connect password generation, validation, and database operations."""

    def __init__(self, database, generator):
        self.database = database
        self.generator = generator

    def create_password(self, length, uppercase, lowercase, digits, symbols):
        return self.generator.generate(length, uppercase, lowercase, digits, symbols)

    def save_record(self, record):
        """Save a password record with a parameterized SQL query."""
        query = '\n        INSERT INTO password_records (\n            website, username, password, password_length,\n            includes_uppercase, includes_lowercase,\n            includes_digits, includes_symbols, created_at\n        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)\n        '
        cursor = self.database.execute(query, record.to_database_tuple())
        record_id = cursor.lastrowid
        self.database.log_action('SAVE', f'Saved record ID {record_id} for {record.website}')
        return record_id

    def get_all_records(self):
        rows = self.database.fetch_all('SELECT * FROM password_records ORDER BY record_id')
        return [PasswordRecord.from_database_row(row) for row in rows]

    def get_record(self, record_id):
        row = self.database.fetch_one('SELECT * FROM password_records WHERE record_id = ?', (record_id,))
        if row is None:
            return None
        return PasswordRecord.from_database_row(row)

    def search_by_website(self, search_text):
        """Search website names using SQL LIKE."""
        rows = self.database.fetch_all('SELECT * FROM password_records WHERE website LIKE ? ORDER BY website', (f'%{search_text}%',))
        return [PasswordRecord.from_database_row(row) for row in rows]

    def search_by_username(self, search_text):
        rows = self.database.fetch_all('SELECT * FROM password_records WHERE username LIKE ? ORDER BY username', (f'%{search_text}%',))
        return [PasswordRecord.from_database_row(row) for row in rows]

    def update_record(self, record_id, website, username):
        """Update the website and username for a saved record."""
        existing = self.get_record(record_id)
        if existing is None:
            return False
        self.database.execute('UPDATE password_records SET website = ?, username = ? WHERE record_id = ?', (website.strip(), username.strip(), record_id))
        self.database.log_action('UPDATE', f'Updated record ID {record_id}')
        return True

    def delete_record(self, record_id):
        """Delete a record after the user confirms in the menu."""
        existing = self.get_record(record_id)
        if existing is None:
            return False
        self.database.execute('DELETE FROM password_records WHERE record_id = ?', (record_id,))
        self.database.log_action('DELETE', f'Deleted record ID {record_id}')
        return True

    def sort_records(self, sort_by='website', descending=False):
        """Sort records in Python, demonstrating list sorting."""
        records = self.get_all_records()
        allowed_fields = {'website': lambda item: item.website.lower(), 'username': lambda item: item.username.lower(), 'length': lambda item: item.password_length, 'date': lambda item: item.created_at}
        if sort_by not in allowed_fields:
            sort_by = 'website'
        records.sort(key=allowed_fields[sort_by], reverse=descending)
        return records

    def get_statistics(self):
        """Use SQL aggregate functions to calculate simple statistics."""
        total_row = self.database.fetch_one('SELECT COUNT(*) AS total FROM password_records')
        average_row = self.database.fetch_one('SELECT AVG(password_length) AS average_length FROM password_records')
        longest_row = self.database.fetch_one('SELECT MAX(password_length) AS longest FROM password_records')
        return {'total': total_row['total'], 'average_length': average_row['average_length'] or 0, 'longest': longest_row['longest'] or 0}

    def get_activity_history(self, limit=20):
        return self.database.fetch_all('SELECT * FROM activity_history ORDER BY history_id DESC LIMIT ?', (limit,))

class InputHelper:
    """Keep input validation in one place."""

    @staticmethod
    def ask_non_empty(prompt):
        while True:
            value = input(prompt).strip()
            if value:
                return value
            print('This field cannot be empty.')

    @staticmethod
    def ask_integer(prompt, minimum=None, maximum=None):
        while True:
            raw_value = input(prompt).strip()
            try:
                value = int(raw_value)
            except ValueError:
                print('Please enter a whole number.')
                continue
            if minimum is not None and value < minimum:
                print(f'Enter a number greater than or equal to {minimum}.')
                continue
            if maximum is not None and value > maximum:
                print(f'Enter a number no greater than {maximum}.')
                continue
            return value

    @staticmethod
    def ask_yes_no(prompt, default=True):
        while True:
            answer = input(prompt).strip().lower()
            if not answer:
                return default
            if answer in ('y', 'yes'):
                return True
            if answer in ('n', 'no'):
                return False
            print('Please type y or n.')

    @staticmethod
    def pause():
        input('\nPress Enter to continue...')

class PasswordGeneratorApp:
    """Main menu and terminal user interface."""

    def __init__(self):
        self.database = DatabaseManager()
        self.generator = PasswordGenerator()
        self.service = PasswordService(self.database, self.generator)
        self.running = True

    def print_header(self, title):
        print('\n' + '=' * 60)
        print(title.center(60))
        print('=' * 60)

    def print_main_menu(self):
        self.print_header('PASSWORD GENERATOR SYSTEM')
        print('1. Generate a new password')
        print('2. Display saved records')
        print('3. Search records')
        print('4. Sort records')
        print('5. Update website or username')
        print('6. Delete a saved record')
        print('7. Check password strength')
        print('8. Show database statistics')
        print('9. Show recent activity')
        print('10. Exit')
        print('-' * 60)

    def choose_character_options(self):
        print('\nChoose the character groups to include:')
        uppercase = InputHelper.ask_yes_no('Uppercase letters (A-Z)? (Y/n): ')
        lowercase = InputHelper.ask_yes_no('Lowercase letters (a-z)? (Y/n): ')
        digits = InputHelper.ask_yes_no('Numbers (0-9)? (Y/n): ')
        symbols = InputHelper.ask_yes_no('Symbols (!@# etc.)? (Y/n): ')
        if not any((uppercase, lowercase, digits, symbols)):
            print('No group selected. Lowercase letters will be used.')
            lowercase = True
        return (uppercase, lowercase, digits, symbols)

    def generate_new_password(self):
        self.print_header('GENERATE PASSWORD')
        website = InputHelper.ask_non_empty('Website or app name: ')
        username = InputHelper.ask_non_empty('Username or email label: ')
        length = InputHelper.ask_integer('Password length (4-128): ', minimum=4, maximum=128)
        uppercase, lowercase, digits, symbols = self.choose_character_options()
        try:
            password = self.service.create_password(length, uppercase, lowercase, digits, symbols)
        except ValueError as error:
            print('Could not generate password:', error)
            return
        strength = self.generator.estimate_strength(password)
        print('\nGenerated password:')
        print(password)
        print('Estimated strength:', strength)
        if InputHelper.ask_yes_no('Save this record in the database? (Y/n): '):
            record = PasswordRecord(website, username, password, length, uppercase, lowercase, digits, symbols)
            record_id = self.service.save_record(record)
            print(f'Record saved successfully. Record ID: {record_id}')
        else:
            print('Record was not saved.')
        InputHelper.pause()

    def display_records(self, records=None, reveal_password=False):
        if records is None:
            records = self.service.get_all_records()
        self.print_header('SAVED PASSWORD RECORDS')
        if not records:
            print('No records found.')
            InputHelper.pause()
            return
        for record in records:
            print(record.summary())
            if reveal_password:
                print('Password:', record.password)
            else:
                print('Password: [hidden]')
            print('-' * 60)
        if not reveal_password:
            print('Passwords are hidden by default.')
            print('Use the reveal option only on a private device.')
        if InputHelper.ask_yes_no('Reveal passwords on this screen? (y/N): ', default=False):
            print('\nWARNING: Do not reveal passwords where others can see.')
            if InputHelper.ask_yes_no('Continue and reveal? (y/N): ', default=False):
                for record in records:
                    print(f'ID {record.record_id} | {record.website} | {record.username} | {record.password}')
        InputHelper.pause()

    def search_records(self):
        self.print_header('SEARCH RECORDS')
        print('1. Search by website')
        print('2. Search by username')
        choice = InputHelper.ask_integer('Choose search type: ', 1, 2)
        term = InputHelper.ask_non_empty('Enter search text: ')
        if choice == 1:
            results = self.service.search_by_website(term)
        else:
            results = self.service.search_by_username(term)
        if results:
            self.display_records(results)
        else:
            print('No matching records were found.')
            InputHelper.pause()

    def sort_records_menu(self):
        self.print_header('SORT RECORDS')
        print('1. Website name')
        print('2. Username')
        print('3. Password length')
        print('4. Creation date')
        choice = InputHelper.ask_integer('Sort by: ', 1, 4)
        field_map = {1: 'website', 2: 'username', 3: 'length', 4: 'date'}
        descending = InputHelper.ask_yes_no('Descending order? (y/N): ', default=False)
        records = self.service.sort_records(field_map[choice], descending)
        self.display_records(records)

    def update_record_menu(self):
        self.print_header('UPDATE RECORD')
        record_id = InputHelper.ask_integer('Record ID to update: ', 1)
        record = self.service.get_record(record_id)
        if record is None:
            print('Record ID was not found.')
            InputHelper.pause()
            return
        print('Current website:', record.website)
        print('Current username:', record.username)
        website = input('New website (Enter to keep current): ').strip()
        username = input('New username (Enter to keep current): ').strip()
        if not website:
            website = record.website
        if not username:
            username = record.username
        if self.service.update_record(record_id, website, username):
            print('Record updated successfully.')
        else:
            print('Record could not be updated.')
        InputHelper.pause()

    def delete_record_menu(self):
        self.print_header('DELETE RECORD')
        record_id = InputHelper.ask_integer('Record ID to delete: ', 1)
        record = self.service.get_record(record_id)
        if record is None:
            print('Record ID was not found.')
            InputHelper.pause()
            return
        print('Selected:', record.summary())
        confirm = InputHelper.ask_yes_no('Are you sure you want to delete this record? (y/N): ', default=False)
        if not confirm:
            print('Deletion cancelled.')
        elif self.service.delete_record(record_id):
            print('Record deleted successfully.')
        else:
            print('Record could not be deleted.')
        InputHelper.pause()

    def check_password_strength(self):
        self.print_header('CHECK PASSWORD STRENGTH')
        print('For privacy, avoid entering a real account password.')
        password = getpass('Enter a sample password to check: ')
        if not password:
            print('No password was entered.')
        else:
            print('Estimated strength:', self.generator.estimate_strength(password))
            print('This is a basic educational estimate, not a security audit.')
        InputHelper.pause()

    def show_statistics(self):
        self.print_header('DATABASE STATISTICS')
        stats = self.service.get_statistics()
        print('Total saved records:', stats['total'])
        print('Average password length:', round(stats['average_length'], 2))
        print('Longest password length:', stats['longest'])
        InputHelper.pause()

    def show_activity(self):
        self.print_header('RECENT ACTIVITY')
        history = self.service.get_activity_history()
        if not history:
            print('No activity has been recorded yet.')
        else:
            for item in history:
                print(f"{item['history_id']}. {item['action']} | {item['details']} | {item['action_time']}")
        InputHelper.pause()

    def run(self):
        """Run until the user chooses Exit."""
        try:
            while self.running:
                self.print_main_menu()
                choice = InputHelper.ask_integer('Enter your choice (1-10): ', 1, 10)
                if choice == 1:
                    self.generate_new_password()
                elif choice == 2:
                    self.display_records()
                elif choice == 3:
                    self.search_records()
                elif choice == 4:
                    self.sort_records_menu()
                elif choice == 5:
                    self.update_record_menu()
                elif choice == 6:
                    self.delete_record_menu()
                elif choice == 7:
                    self.check_password_strength()
                elif choice == 8:
                    self.show_statistics()
                elif choice == 9:
                    self.show_activity()
                elif choice == 10:
                    self.exit_application()
        except (KeyboardInterrupt, EOFError):
            print('\nProgram interrupted.')
            self.exit_application()

    def exit_application(self):
        print('\nThank you for using Password Generator System.')
        self.running = False
        try:
            self.database.close()
        except sqlite3.Error:
            pass

def linear_search_record(records, target_id):
    """Linear search: inspect each record until the ID matches."""
    for record in records:
        if record.record_id == target_id:
            return record
    return None

def binary_search_sorted_ids(records, target_id):
    """
    Binary search works only when records are sorted by record ID.
    This helper demonstrates the algorithm separately from SQL search.
    """
    sorted_records = sorted(records, key=lambda item: item.record_id or 0)
    left = 0
    right = len(sorted_records) - 1
    while left <= right:
        middle = (left + right) // 2
        current_id = sorted_records[middle].record_id
        if current_id == target_id:
            return sorted_records[middle]
        if current_id < target_id:
            left = middle + 1
        else:
            right = middle - 1
    return None

def remove_duplicate_strings(values):
    """Return unique strings while preserving their first-seen order."""
    unique_values = []
    seen_values = set()
    for value in values:
        normalized = value.strip().lower()
        if normalized not in seen_values:
            seen_values.add(normalized)
            unique_values.append(value)
    return unique_values

def demonstrate_dsa_helpers():
    """Small optional demonstration for explaining DSA in the viva."""
    sample = ['Email', 'Bank', 'Email', 'Shopping', 'bank']
    unique = remove_duplicate_strings(sample)
    print('Original sample list:', sample)
    print('After duplicate removal:', unique)
    print('This demonstrates list traversal and set-based lookup.')

def main():
    """Create and run the application."""
    app = PasswordGeneratorApp()
    app.run()
if __name__ == '__main__':
    main()
