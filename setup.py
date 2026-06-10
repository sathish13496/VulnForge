from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="linarmor",
    version="1.0.0",
    author="Sathish Kumar",
    author_email="sathishkumar@example.com",
    description="Linux Security Misconfiguration Discovery Framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/sathish13496/LinArmor",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "linarmor": [
            "templates/**/*",
            "static/**/*",
            "data/**/*",
        ]
    },
    python_requires=">=3.10",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "linarmor=linarmor.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Topic :: Security",
        "Environment :: Web Environment",
    ],
)
