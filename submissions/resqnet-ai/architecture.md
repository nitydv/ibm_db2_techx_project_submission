# ResQNet AI – System Architecture

## 1. Overview

ResQNet AI is an intelligent emergency response platform developed using Python and Flask. It helps users report emergencies and supports monitoring and response coordination.

## 2. Technology Stack

* Frontend: HTML, CSS, JavaScript
* Backend: Python, Flask
* Primary Database: MySQL
* Additional Database: IBM Db2
* Database Connectivity: ibm_db

## 3. System Components

### Frontend

Provides user interfaces for emergency reporting, dashboards, maps, analytics and women's safety.

### Backend

Flask handles user requests, processes emergency reports and connects the application to databases.

### MySQL Database

Stores the primary application data, including emergency incident records.

### IBM Db2 Integration

IBM Db2 provides additional incident data storage. When an incident is successfully saved in MySQL, the application also synchronizes its details with IBM Db2.

## 4. Data Flow

1. User submits an emergency report.
2. Flask receives and validates the request.
3. Incident information is saved in MySQL.
4. The application sends the incident data to IBM Db2.
5. The dashboard displays incident information for monitoring.

## 5. Key Modules

* Emergency Reporting
* Command Center Dashboard
* Emergency Map
* Responder Management
* Analytics
* Women Safety Center
* Anonymous Crime Reporting

## 6. Team

Team Name: ETHIX

Developer: Shadab Khan
