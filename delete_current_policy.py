

def main():
  with open('delete_current_policy.txt', 'w') as file:
    for i in range(1, 9001):
      file.write(f'delete {i}\n')

if __name__ == "__main__":
    main()