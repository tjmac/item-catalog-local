# Project: Item Catalog
#### **Goal**: 
Develop an application that provides a list of items within a variety of categories as well as provide a user registration and authentication system. Registered users will have the ability to post, edit and delete their own items.

- Project Specification provided [here](https://docs.google.com/document/d/e/2PACX-1vT7XPf0O3oLCACjKEaRVc_Z-nNoG6_ssRoo_Mai5Ce6qFK_v7PpR1lxmudIOqzKo2asKOc89WC-qpfG/pub?embedded=true). Additional rubric [here](https://review.udacity.com/#!/rubrics/2008/view)
- In order to meet the `pycodestyle` or `PEP8` style recommendations I used `autopep8 --in-place --aggressive --aggressive views.py` to assist with format corrections.

#### **Assumptions**: 
This README will assume: 
1. You have the dependencies installed to run a virtual machine and vagrant environment.

#### **Application Functionality**:
1. Provides Google authentication flow for ease of user log-in.
2. Logged in users are able to add categories, add, edit and delete items.

#### **Instructions to run**:
- Once you have downloaded this `.zip` file, please unzip and enter the folder. Use `vagrant up` to build the virtual machine from the VagrantFile. Once it is complete use `vagrant ssh`. Last, enter the shared folder `/vagrant/catalog/` and run the application with `python application.py`.