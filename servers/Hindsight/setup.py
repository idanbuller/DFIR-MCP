from setuptools import setup, find_packages

setup(
    name="hindsight-mcp-server",
    version="1.0.0",
    description="MCP Server for Hindsight Browser Forensics Tool",
    author="Your Name",
    author_email="your.email@example.com",
    packages=find_packages(),
    install_requires=[
        "mcp>=1.0.0",
        "pydantic>=2.0.0",
        "bottle>=0.12.8",
        "pycryptodome>=3.4.6",
        "pytz>=2016.4",
        "python-dateutil>=2.5.3",
    ],
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "hindsight-mcp=hindsight_mcp_server:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)
