import os, subprocess, shutil, site
from setuptools import setup, find_packages
from setuptools.command.install import install

class CustomBuildCommand(install):
	"""Customized setuptools install command - runs `make` to build the shared library."""
	def run(self):
		print("***** Current directory:", os.getcwd())
		# Run the Makefile before installation
		make_path = os.path.join(os.path.dirname(__file__), 'lib', 'Makefile')
		if os.path.exists(make_path):
			make_dir = os.path.dirname(make_path)
			subprocess.check_call(['make', 'build-sl'], cwd=make_dir)

			src_so_file = os.path.join(os.getcwd(), './lib/target/release/libfrost_ed25519.so')
			print("***** source file:", os.getcwd())

			site_packages_dir = site.getsitepackages()[0]
			package_name = self.distribution.get_name()
			target_dir = os.path.join(site_packages_dir, package_name)  # Adjust the directory name as needed
			target_so_file = os.path.join(target_dir, 'libfrost_ed25519.so')
			
			os.makedirs(os.path.dirname(target_so_file), exist_ok=True)
			shutil.copy(src_so_file, target_so_file)
		install.run(self)

setup(
    name='frost_ed25519',
    version='0.1.0',
    package_dir={'': 'support/py'},
    packages=find_packages(where='support/py'),
    include_package_data=True,
    cmdclass={
        'install': CustomBuildCommand,
    },
)
