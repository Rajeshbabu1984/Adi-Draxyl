import os

def calculator():
    while True:
        os.system('cls')  # Clear screen
        print("-" * 30)
        print("         CALCULATOR")
        print("-" * 30)
        
        num1 = float(input("Enter your 1st number: "))
        num2 = float(input("Enter your 2nd number: "))
        operation = input("Enter operation (+, -, *, /): ")
        
        if operation == '+':
            result = num1 + num2
            print(f"The result is: {result}")
        elif operation == '-':
            result = num1 - num2
            print(f"The result is: {result}")    
        elif operation == '*':
            result = num1 * num2
            print(f"The result is: {result}")    
        elif operation == '/':   
            if num2 != 0:
                result = num1 / num2
                print(f"The result is: {result}")
            else:
                print("Error: Division by zero is not allowed.")
        else:
            print("Operation not supported.")
        
        print()
        again = input("Calculate again? (y/n): ").lower()
        if again != 'y':
            print("Thanks for using the calculator! 👋")
            break

calculator()
