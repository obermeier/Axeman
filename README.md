<p align="center">
    <img align="center" style="width: 300px" src="https://github.com/CaliDog/Lumberjack/raw/master/img/logo.png">
    <h3 align="center">Axeman</h3>
    <p align="center">Harvester of certificates, bearer of flannel.</p>
</p>

## What?
Axeman is a utility for downloading, parsing, and storing <a href="https://www.certificate-transparency.org/what-is-ct">Certificate Transparency Lists</a> using python3's concurrency and multi-processing. Its aim is to download and parse certificates relatively quickly and efficiently, storing them in CSVs on the local filesystem. 

## Installing it
Installation should be super straight forward, but you need a newer version of python (3.5+) to run it.

```
pip3 install axeman
```

## Usage

```
$ axeman -h
usage: axeman [-h] [-f LOG_FILE] [-l] [-u CTL_URL] [-z CTL_OFFSET]
              [-o OUTPUT_DIR] [-v] [-c CONCURRENCY_COUNT] [-p PROGRESS_FILE]

Pull down certificate transparency list information

optional arguments:
  -h, --help            show this help message and exit
  -f LOG_FILE           Location for the axeman log file
  -l                    List all available certificate lists
  -u CTL_URL            Retrieve this CTL only
  -z CTL_OFFSET         The CTL offset to start at
  -o OUTPUT_DIR         The output directory to store certificates in
  -v                    Print out verbose/debug info
  -c CONCURRENCY_COUNT  The number of concurrent downloads to run at a time
  -p PROGRESS_FILE      File hold the progress
```

## Demo

This is Axeman dumping information on each CTL known by certificate-transparency.org
```
$ axeman -l
```
<img src="https://github.com/CaliDog/Lumberjack/raw/master/img/demo2.gif">
This is axeman running in verbose mode and pulling down the SkyDiver CTL

```
$ axeman -v -u 'ct.googleapis.com/skydiver'
```
<img src="https://github.com/CaliDog/Lumberjack/raw/master/img/demo.gif">
