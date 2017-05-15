from setuptools import setup
from sshhoneypot import __version__

setup(
    name='sshhoneypot',
    version=__version__,
    description='Python 3 SSH Honeypot',
    long_description='?',
    url='https://github.com/sirMackk/ssh-honeypot',
    author='Matt O.',
    author_email='matt@mattscodecave.com',
    license='?',
    keywords='asynchronous ssh honeypot security',
    packages=['sshhoneypot'],
    include_package_data=True,
    entry_points={
        'console_scripts': [
            'ssh-honeypot = sshhoneypot.__main__:main'
        ]
    },
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.5',
        'Topic :: Security',
        'Topic :: Utilities',
    ],
)
