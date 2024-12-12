import re


def assess_password_strength(password):
    # Criteria for password strength
    feedback_messages = []
    length_criteria = len(password) >= 8
    if not length_criteria:
        feedback_messages.append("Password is less than 8 characters.")

    uppercase_criteria = bool(re.search(r'[A-Z]', password))
    if not uppercase_criteria:
        feedback_messages.append("Password is missing uppercase letter(s).")

    lowercase_criteria = bool(re.search(r'[a-z]', password))
    if not lowercase_criteria:
        feedback_messages.append("Password is missing lowercase letter(s).")

    digit_criteria = bool(re.search(r'\d', password))
    if not digit_criteria:
        feedback_messages.append("Password is missing digit(s).")

    special_char_criteria = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
    if not special_char_criteria:
        feedback_messages.append("Password is missing special character(s).")

    # Calculate strength score
    score = sum([length_criteria, uppercase_criteria, lowercase_criteria, digit_criteria, special_char_criteria])

    # Feedback based on score
    feedback = {
        5: "Excellent! Your password is very strong.",
        4: "Good! Your password is strong, but could be improved.",
        3: "Fair. Your password is okay, but consider adding more diverse characters.",
        2: "Weak. Consider making your password longer and adding different types of characters.",
        1: "Very weak. Your password is too simple.",
        0: "Invalid. Your password does not meet any of the criteria."
    }

    if score == 5:
        feedback_messages.append(feedback[score])

    return score, feedback[score], feedback_messages


def main():
    password = input("Enter your password: ")
    score, strength_feedback, feedback_messages = assess_password_strength(password)

    print(f"Password Strength: {strength_feedback}")
    if feedback_messages:
        print("Details:")
        for message in feedback_messages:
            print(f"- {message}")


if __name__ == "__main__":
    main()
