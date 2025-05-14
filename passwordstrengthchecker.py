#!/usr/bin/env python3
import tkinter as tk
from tkinter import messagebox
import string
import logging

# Set up logging to diagnose hangs
logging.basicConfig(filename='password_checker.log', level=logging.DEBUG, 
                    format='%(asctime)s %(levelname)s: %(message)s')

def assess_password_strength(password):
    logging.debug("Assessing password strength")
    feedback = []
    length = len(password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)
    
    # Generate suggestions for unmet criteria
    if length < 8:
        feedback.append("Password should be at least 8 characters long.")
    if not has_upper:
        feedback.append("Add at least one uppercase letter.")
    if not has_lower:
        feedback.append("Add at least one lowercase letter.")
    if not has_digit:
        feedback.append("Include at least one number.")
    if not has_special:
        feedback.append("Add at least one special character (e.g., !, @, #).")
    
    # Determine strength
    if length >= 8 and has_upper and has_lower and has_digit and has_special:
        strength = "Strong"
        if not feedback:
            feedback.append("Your password looks great!")
    elif length >= 6 and (has_upper or has_lower) and has_digit:
        strength = "Moderate"
    else:
        strength = "Weak"
    
    logging.debug(f"Strength: {strength}, Feedback: {feedback}")
    return strength, feedback

def check_password():
    try:
        password = password_entry.get()
        if not password:
            messagebox.showwarning("Input Error", "Please enter a password.")
            return
        
        strength, feedback = assess_password_strength(password)
        # Format message with strength and suggestions
        message = f"Your password strength is: {strength}\n\nSuggestions:\n"
        message += "\n".join(f"- {item}" for item in feedback) if feedback else "- None"
        messagebox.showinfo("Password Strength", message)
    except Exception as e:
        logging.error(f"Error in check_password: {str(e)}")
        messagebox.showerror("Error", f"Failed to process: {str(e)}")

try:
    # Set up the GUI
    root = tk.Tk()
    root.title("Password Strength Checker")
    root.geometry("400x200")
    root.resizable(False, False)
    logging.debug("GUI initialized")

    # Create and place widgets
    tk.Label(root, text="Enter Password:", font=("Arial", 12)).grid(row=0, column=0, padx=10, pady=10)
    password_entry = tk.Entry(root, show='*', width=30, font=("Arial", 12))
    password_entry.grid(row=0, column=1, padx=10, pady=10)
    check_button = tk.Button(root, text="Check Strength", font=("Arial", 12, "bold"), 
                            command=check_password, bg="#4CAF50", fg="white", padx=10, pady=5)
    check_button.grid(row=1, column=0, columnspan=2, padx=10, pady=10)

    # Run the GUI event loop
    root.mainloop()
except tk.TclError as e:
    logging.error(f"Tkinter initialization failed: {str(e)}")
    print(f"Error: Tkinter failed to initialize. Try 'xvfb-run python3 password_checker.py' or check display settings.")
except Exception as e:
    logging.error(f"Unexpected error: {str(e)}")
    print(f"Error: {str(e)}. Check logs in password_checker.log for details.")
