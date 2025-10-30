import os

def clean_migrations(root_dir):
    for foldername, subfolders, filenames in os.walk(root_dir):
        # Check if directory is a migrations folder
        if os.path.basename(foldername) == 'migrations':
            for filename in filenames:
                # Skip __init__.py
                if filename != '__init__.py':
                    filepath = os.path.join(foldername, filename)
                    try:
                        os.remove(filepath)
                        print(f"Deleted: {filepath}")
                    except Exception as e:
                        print(f"Failed to delete {filepath}: {e}")

if __name__ == "__main__":
    # Change '.' to your Django project root if needed
    clean_migrations('.')
    print("Migrations cleaned successfully.")