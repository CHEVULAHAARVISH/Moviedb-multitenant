# moviedb

## Setup

### Install postgres
`brew install postgresql`

#### Setup virtual environment
`python3 -m venv venv`

#### Activate virtual environment
`source venv/bin/activate`

#### Install required packages
`pip3 install -r requirements.lock`

#### Create DB and Run migrations
`dropdb movie_db; createdb movie_db; flask db upgrade`

#### Run dev server
`flask run`

