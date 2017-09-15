from setuptools import setup

setup(name='torantula',
      version='0.1',
      description='Tool for handling stream isolation in Tor',
      url='https://github.com/SecurityInnovation/Torantula',
      author='Garrett M',
      license='MIT',
      packages=['torantula'],
      install_requires=[
          'PySocks',
          'stem',
      ])
