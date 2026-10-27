# SHORT DESCRIPTION:

A menu-driven Password Generator System built in Python using SQLite database storage to generate customizable random passwords, estimate password strength, manage saved password records, and track recent activities.

# FEATURES:

1. **Generate Passwords:** Creates random passwords with customizable length and combinations of uppercase letters, lowercase letters, digits, and symbols.
2. **Save and Display Records:** Stores generated passwords with website names, usernames, password length, and creation date in the database.
3. **Search Records:** Searches saved password records by website name or username.
4. **Update and Delete Records:** Allows users to modify website names or usernames and delete saved password records with confirmation.
5. **Password Strength Checker:** Estimates password strength as Weak, Moderate, or Strong based on length and character variety.
6. **Sort Records:** Sorts saved records by website, username, password length, or creation date in ascending or descending order.
7. **Database Statistics:** Displays the total number of saved records, average password length, and longest password length.
8. **Activity History:** Tracks record-saving, updating, and deletion activities with timestamps.

# DATA STRUCTURES AND TECHNOLOGIES USED:

- **Python:** Main programming language.
- **SQLite3 and SQL:** Database creation, storage, searching, updating, deleting, and retrieving records.
- **OOP (Object-Oriented Programming):** Uses classes such as `DatabaseManager`, `PasswordRecord`, `PasswordGenerator`, and `PasswordService`.
- **Lists and Sets:** Store and sort records, generate password characters, and demonstrate duplicate removal.
- **Searching Algorithms:** Includes linear search and binary search helper functions.
- **Python Libraries:** Uses `secrets`, `string`, `datetime`, and `getpass` for secure random generation, character selection, timestamps, and hidden password input.

# DATABASE AUTOMATICALLY CREATED:

The program automatically creates a SQLite database named `passwords.db` containing two tables:

- **password_records:** Stores saved passwords, website names, usernames, password length, selected character options, and creation timestamps.
- **activity_history:** Stores actions performed on password records, their details, and timestamps.

# HOW TO RUN:

1. Install Python on your computer.
2. Save the program as `password_generator.py`.
3. Open a terminal or command prompt in the folder containing the file.
4. Run the command: `python password_generator.py`
5. Use the menu to generate, save, search, sort, update, delete, and manage password records.

# ABOUT:

This project demonstrates Python programming, object-oriented programming, SQL database management, random password generation, searching and sorting algorithms, input validation, and activity tracking through a simple command-line interface.
