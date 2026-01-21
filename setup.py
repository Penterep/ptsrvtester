import setuptools

with open("ptsrvtester/_version.py") as f:
    __version__ = f.readline().split('"')[1]

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="ptsrvtester",
    description="Application server penetration testing tool (Penterep tool)",
    version=__version__,
    author="Penterep",
    author_email="xvlkov03@vutbr.cz",
    url="https://www.penterep.com/",
    license="GPLv3+",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: Implementation :: CPython",
        "Environment :: Console",
        "Topic :: Security",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
    ],
    python_requires=">=3.12",
    install_requires = [
    "cryptography>=42.0.8",
    "dnspython>=2.7.0",
    "impacket>=0.12.0",
    "ldap3>=2.9.1",
    "ptlibs>=1.0.20,<2",
    "pysnmp>=7.1.20",
    "python-whois>=0.9.5",
    "paramiko",
    "beautifulsoup4",
    "httpx",
    "h2",
    "lxml",
    "ssh_audit",
    "ntlm-auth",
],
    entry_points={"console_scripts": ["ptsrvtester = ptsrvtester.ptsrvtester:main"]},
    include_package_data=True,
    long_description=long_description,
    long_description_content_type="text/markdown",
)
