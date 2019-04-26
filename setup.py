import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="silverpeak",
    version="0.0.3.3",
    author="Alex Gittings, Adam Jarvis",
    author_email="alexgit@hotmail.co.uk, adamjohnjarvis1@gmail.com",
    description="A package to allow you to interact with the Silver Peak Orchestrator API",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/minitriga/silverpeak_python",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
