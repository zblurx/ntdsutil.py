from setuptools import setup

setup(
    name="ntdsutil.py",
    version="1.0.0",
    author="zblurx",
    author_email="seigneuret.thomas@pm.me",
    description="Dump ntds with ntdsutil remotely",
    long_description="README.md",
    long_description_content_type="text/markdown",
    url="https://github.com/zblurx/ntdsutil.py",
    license="MIT",
    install_requires=[
        "impacket"
    ],
    python_requires='>=3.6',
    scripts=["ntdsutil.py"]
)
