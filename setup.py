import os, subprocess, shutil, site
from setuptools import setup, find_packages
from setuptools.command.install import install

class CustomBuildCommand(install):
	"""Customized setuptools install command - runs `make` to build the shared library."""
	def run(self):
		# Run the Makefile before installation
		make_path = os.path.join(os.path.dirname(__file__), 'Makefile')
		if os.path.exists(make_path):
			make_dir = os.path.dirname(make_path)
			subprocess.check_call(['make', 'install'], cwd=make_dir)

			site_packages_dir = site.getsitepackages()[0]
			package_name = self.distribution.get_name()
			target_dir = os.path.join(site_packages_dir, package_name)  # Adjust the directory name as needed

			os.makedirs(target_dir, exist_ok=True)

			for module in ['ed25519', 'secp256k1', 'secp256k1_tr']:
				src_so_file = os.path.join(os.getcwd(), f"./target/release/libfrost_{module}.so")
				target_so_file = os.path.join(target_dir, f"libfrost_{module}.so")
				shutil.copy(src_so_file, target_so_file)

		install.run(self)

setup(
    name='frost_lib',
    version='0.1.0',
    package_dir={'': 'support/py'},
    packages=find_packages(where='support/py'),
    include_package_data=True,
    cmdclass={
        'install': CustomBuildCommand,
    },
)
