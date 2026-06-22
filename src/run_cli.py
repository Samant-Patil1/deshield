import sys
from src import main as main_module


def main():
    sys.argv = ["deshield"] + sys.argv[1:]
    main_module.main()


if __name__ == "__main__":
    main()
