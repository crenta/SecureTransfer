import os
import shutil

# Get the absolute path of the current directory (SecureSender folder)
base_dir = os.path.abspath(os.path.dirname(__file__))

# Define paths for the spec file, build folder, dist folder, and executable
spec_file = os.path.join(base_dir, "secure_receiver.spec")
build_dir = os.path.join(base_dir, "build")
dist_dir = os.path.join(base_dir, "dist")
exe_file = os.path.join(dist_dir, "secure_receiver.exe")
target_exe = os.path.join(base_dir, "secure_receiver.exe")

# Delete the .spec file if it exists
if os.path.exists(spec_file):
    os.remove(spec_file)
    print(f"Deleted spec file: {spec_file}")
else:
    print(f"Spec file not found: {spec_file}")

# Delete the build folder if it exists
if os.path.exists(build_dir):
    shutil.rmtree(build_dir)
    print(f"Deleted build folder: {build_dir}")
else:
    print(f"Build folder not found: {build_dir}")

# Move secure_receiver.exe from dist to the main folder
if os.path.exists(exe_file):
    shutil.move(exe_file, target_exe)
    print(f"Moved executable from {exe_file} to {target_exe}")
else:
    print(f"Executable not found in dist folder: {exe_file}")

# Delete the dist folder
if os.path.exists(dist_dir):
    shutil.rmtree(dist_dir)
    print(f"Deleted dist folder: {dist_dir}")
else:
    print(f"Dist folder not found: {dist_dir}")
