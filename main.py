import bcrypt

password = 'Magic123'

def hash_password(password):

    binary_password = password.encode('utf-8') # Convert to binary format  
    salt = bcrypt.gensalt() # Generate a salt
    hashed_password = bcrypt.hashpw(binary_password, salt) # Hash the password with the salt
    return hashed_password.decode('utf-8') # Convert back to string formated_passworded password



def validate_password(password, hashed):
    psw = password.encode('utf-8')
    hash_ = hashed.encode('utf-8')
    return bcrypt.checkpw(psw, hash_)

def register_user():
   user_name = input("Enter username: ")
   user_password = input("Enter password: ")
   hash = hash_password(user_password)
   with open("users.txt", "a") as f:
       f.write(f"{user_name},{hash}\n")   
       
   print("User registered successfully.")

def login_user():
   user_name = input("Enter username: ")
   user_password = input("Enter password: ")
   with open("users.txt", "r") as f:
       lines = f.readlines()
       for line in lines:
           name,hash = line.strip().split(",")
           if name == user_name:
              return validate_password(user_password, hash)
   return False

#print(register_user()) # Should register a new user

#print(login_user()) # Should return True if credentials are correct, else False

# Display menu options
def menu(): 
    print('Welcome to the User Authentication System')
    print('choose from the following options:')
    print('1. Register')
    print('2. Login')
    print('3. Exit')

def main(_):
     while True:
        menu()
        choice = input(' > ')
        if choice == '1':
            register_user()
        elif choice == '2':
            login_user()
        elif choice == '3':
            print('Exiting the system. Goodbye!')
            break


if __name__ == "__main__":
    main(None)