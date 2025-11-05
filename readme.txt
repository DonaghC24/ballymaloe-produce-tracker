https://supabase.com/docs/guides/database/connecting-to-postgres#connection-pooler
https://supabase.com/docs/reference/python/introduction




# Ballymaloe Produce Tracker 

A lightweight web application designed to help Ballymaloe's head gardener and kitchen staff track harvested produce, view availability, and streamline daily ordering.

##  Project Overview

the system supports role-based access for gardeners and chefs, allowing them to log harvests and view available produce in real time. The goal is to improve communication between the garden and kitchen while reducing waste and improving sustainability.

##  Tech Stack

- **Backend**: Flask (Python)
- **Database**: Supabase (PostgreSQL)
- **Frontend**: HTML, Bootstrap 5
- **Authentication**: Supabase Auth + Flask-Login
- **Version Control**: Git + GitHub

##  User Roles

- **Head Gardener**: Logs daily harvested produce
- **Chef**: Views available produce and places daily orders
- **Manager (Planned)**: Views reports on usage and waste

##  Completed Features (Iteration 1)

- Harvest logging form with validation
- Supabase integration for storing harvest data
- Produce list view for chefs
- Role-based login system

##  Planned Features (Iteration 2)

- Filtering produce options when logging harvest
- Chef order form for daily produce requests
- Manager dashboard for reporting (future)

