
# TASK MANAGER - MERN 

 The task manager app is a versatile productivity tool that combines task management, to-do lists, and note-taking functionalities. Users can efficiently organize, prioritize, and track their tasks, create to-do lists for better task categorization, and take notes for important information. The user-friendly interface, synchronization across devices, reminders, and optional collaboration features make it a comprehensive solution for streamlined productivity.

# Intrtoduction

 Welcome to our Task Manager App – your all-in-one solution for efficient task management, seamless to-do list organization, and convenient note-taking. This application is designed to enhance your productivity by providing a unified platform for managing your daily activities. Whether you're an individual striving for personal organization or part of a collaborative team, our app is here to simplify your workflow.
# Features
# Task Management :

Create, edit, and delete tasks with ease.

Specify due dates, priorities, and track task status effortlessly.

Categorize and filter tasks for a customized and organized view.

Get notify through the app on bell icon

# To-Do :

Create lists to organize tasks based on projects, categories, or any criteria.

Break down tasks into manageable sections for focused execution.

# Notes - Functionality :

Capture ideas, thoughts, and important information effortlessly.

Edit and organize notes with rich text formatting and multimedia attachments.

# DEMO
## Login Page
![Screenshot (55)](https://github.com/John12356/Task-Manager--First-MERN/assets/91779049/e6c16d98-9342-4d37-b17c-7035fcbd77dd)
## Home Page
![Screenshot (65)](https://github.com/John12356/Task-Manager--First-MERN/assets/91779049/d9e4fc89-d1ad-4604-b610-6842e5e71b48)
## To-Do Page
![Screenshot (61)](https://github.com/John12356/Task-Manager--First-MERN/assets/91779049/45f2bb36-08db-4e4e-9c6d-ea84845469b1)
## Task Page
![Screenshot (62)](https://github.com/John12356/Task-Manager--First-MERN/assets/91779049/0ac74f42-3851-4102-a2f9-ee609ded1eba)
## Notes Page
![Screenshot (63)](https://github.com/John12356/Task-Manager--First-MERN/assets/91779049/a5726406-2b8b-445b-8ee9-01bd1e64d79c)
## Dark - Mode
![Screenshot (64)](https://github.com/John12356/Task-Manager--First-MERN/assets/91779049/30f8cd99-c136-4721-b552-6a146827ed88)

## How To Run
Create the file `BackEnd/config.env` with your Atlas URI and the server port:

**FrontEnd**
```
REACT_APP_API_URL = your backend api with port
```
**BackEnd**
```
MONGO_URL = your mongoDb url either from atlas or from localhost shell
```
If you are going Authenticate with Facebook and Google Through PassportJs Stratgy...
```
GOOGLE_CLIENT_ID = your google app clint id
GOOGLE_CLIENT_SECRET = your google app client secret
FACEBOOK_CLIENT_ID = your facebook app clint id
FACEBOOK_CLIENT_SECRET = your facebook app client secret
FRONTEND_DOMAIN = you react app url with port
SESSION_SECRET = anything you want
JWT_SECRET_KEY = anything you want
```
Start server i.e., BackEnd:
```
cd Task-Manager--First-MERN/BackEnd
npm install
npm start
```
Start Client i.e., FrontEnd:
```
cd Task-Manager--First-MERN/FrontEnd
npm install
npm start or npm run dev
```
