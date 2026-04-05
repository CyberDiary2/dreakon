from setuptools import setup, find_packages

setup(
    name="dreakon",
    version="0.1.0",
    packages=find_packages(),
    install_requires=open("requirements.txt").read().splitlines(),
    entry_points={
        "console_scripts": [
            "dreakon=dreakon.cli:main",
        ],
    },
    python_requires=">=3.11",
    package_data={
        "dreakon": ["wordlists/*.txt"],
    },
)
