import os
import shutil

def clean_migrations(root_dir):
    # Walk top-down so we can prune .venv from traversal
    for foldername, subfolders, filenames in os.walk(root_dir, topdown=True):
        # prevent descending into .venv if present at this level
        if '.venv' in subfolders:
            subfolders[:] = [d for d in subfolders if d != '.venv']

        # also skip any path already inside a .venv folder
        if '.venv' in foldername.split(os.sep):
            continue

        base = os.path.basename(foldername)

        # remove __pycache__ directories entirely
        if base == '__pycache__':
            try:
                shutil.rmtree(foldername)
                print(f"Deleted directory: {foldername}")
            except Exception as e:
                print(f"Failed to delete directory {foldername}: {e}")
            continue

        # clean migrations directories but keep __init__.py
        if base == 'migrations':
            for fname in filenames:
                if fname == '__init__.py':
                    continue
                fpath = os.path.join(foldername, fname)
                try:
                    os.remove(fpath)
                    print(f"Deleted: {fpath}")
                except Exception as e:
                    print(f"Failed to delete {fpath}: {e}")

if __name__ == "__main__":
    # adjust root if needed
    clean_migrations('.')
    print("Migrations and __pycache__ cleaned (excluded .venv).")