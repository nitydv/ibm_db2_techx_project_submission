# ResQNet AI – System Architecture

## 1. Overview

ResQNet AI is a Flask-based emergency response platform that connects users, administrators, and emergency responders through a centralized system.

## 2. Architecture Components

### Frontend

* HTML
* CSS
* JavaScript
* Jinja2 Templates

### Backend

* Python
* Flask Framework
* AI-Based Incident Analysis

### Databases

* MySQL: Primary database for emergency records.
* IBM Db2: Additional database for synchronized emergency incident records.

## 3. System Workflow

1. User submits an emergency report.
2. Flask receives the report.
3. AI analysis determines incident severity and priority.
4. Incident details are stored in MySQL.
5. The application synchronizes the incident with IBM Db2.
6. Administrators monitor incidents through the command center dashboard.
7. Responders can be managed and assigned to incidents.

## 4. IBM Db2 Integration

IBM Db2 is integrated using the Python `ibm_db` driver.

The application connects to the RESQNET database and stores synchronized incident records in the `RESQNET_INCIDENTS` table.

The synchronization includes:

* Source MySQL Incident ID
* Emergency Type
* Description
* Latitude and Longitude
* Severity
* Priority
* AI Reason

## 5. Technology Stack

* Python and Flask
* MySQL
* IBM Db2 Community Edition
* IBM Db2 Python Driver
* HTML, CSS and JavaScript

## 6. Benefits

* Centralized emergency monitoring
* Additional database storage through IBM Db2
* Improved incident tracking
* AI-assisted incident prioritization
* Better emergency response coordination

## 7. Future Scope

* Real-time responder tracking
* Advanced AI-based emergency prediction
* Mobile application integration
* Automated emergency notifications
