<p align='center'>
  <h5 align='center'>ABOUT</h5>
  <p align='center'>
    A fast and easy to use cross-platform file encryption app.
  </p>
</p>

<p align='center'>
  <a href='https://example.com'>
    <img src='https://img.shields.io/badge/status-indev-blue?style=for-the-badge' height='25'>
  </a>
  <a href='https://example.com'>
    <img src='https://img.shields.io/badge/build-success-blue?style=for-the-badge' height='25'>
  </a>
  <a href='https://github.com/rust-dev-tools/fmt-rfcs/blob/master/guide/guide.md'>
    <img src='https://img.shields.io/badge/code_style-rust-blue?style=for-the-badge' height='25'>
  </a>
</p>

## What is Sileo?

Sileo is a free and open source cross-platform application designed to make it easier for people to encrypt files and information before uploading them to cloud storage services like Dropbox or Google Drive.

## Why should I use it?

If you think about it, the "cloud" is basically just someone elses computer. Whenever you upload something to the "cloud", your files and information is stored on a server located somewhere near you. This means that your data is open to anyone that has physical access to the "computer". With Sileo, you will be able to easily encrypt your data by simply dragging and dropping them into the application. Sileo first uses the SHA256 algorithm to secure your data with PGP, then applies the MD5 hashing algorithm before sending them off to your cloud storage of choice or to be stored on your computer.

## How it works

When you tell Sileo to process your files, it:
1. (If needed) will archive the folder into a tar file
2. Compresses the file with gzip
2. Secures your data with the SHA256 algorithm via symmetrical PGP encryption
3. Applies an MD5 hashing algorithm in order to ensure data integrity, i.e. your data has not been modified after being downloaded from the cloud
4. Uploads the compressed, optimized and secured file to the cloud storage of your choice or spit it out so you can do whatever you wish to do with it