# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project Overview

**Ride-Partner-1** is a ride-sharing booking platform with user authentication, admin management, and booking system. It uses Express.js as the backend framework with both PostgreSQL (primary data) and MongoDB (contact messages) databases.

## Architecture

### Technology Stack
- **Backend**: Node.js with Express.js (ES modules)
- **Databases**: 
  - PostgreSQL (hosted on Neon) for users, bookings, admins, and booking status history
  - MongoDB (Atlas) for contact messages
- **Authentication**: Passport.js with local strategy, bcrypt for password hashing, express-session for session management
- **Frontend**: EJS templates with Tailwind CSS
- **Hosting**: Render (detection via `PG_HOST` check for SSL configuration)

### Core Components

**Database Layer** (`index.js` lines 38-63, 102-212):
- PostgreSQL client initialization with Neon (SSL enabled by default)
- MongoDB connection with Mongoose
- Four main tables: `users`, `bookings`, `admins`, `booking_status_history`
- Auto-initialization functions create tables and indexes on startup

**Authentication System** (lines 805-848):
- Passport local strategy for email/password login
- User serialization uses full user object in session
- Admin role detection via `req.user.role === 'admin'`
- Protected routes check `req.isAuthenticated()` and role

**Booking System** (lines 104-123, 427-507, 618-665):
- Booking creation with user data and status tracking
- Status transitions logged to `booking_status_history` table
- Admin-only status update endpoint with audit trail
- Query parameters pass booking state (success/error) to frontend

**Contact Messages** (MongoDB, lines 67-101, 263-392):
- Mongoose schema with required fields (name, email, phone, message)
- Status field for tracking (new/read/replied)
- Admin API endpoints for retrieving and deleting messages

### Route Structure
- `/` and `/signup`: Public signup page
- `/sign`: Login page (redirects to profile if authenticated)
- `/services` and `/index5`: Booking form (passes `?booking` query param)
- `/admin-*`: Admin-only routes (login, signup, dashboard, logout)
- `/bookings`, `/booking-history/:id`, `/update-booking/:id`: Protected admin APIs
- `/api/contacts`: Admin contact message management
- `/profile`: Protected user profile display

## Common Commands

```bash
# Start the application
npm start

# The app listens on PORT environment variable (default: 3000)
# With database initialization logs and auto-table creation
```

## Development Notes

### Environment Setup
The `.env` file contains:
- `MONGODB_URI`: MongoDB Atlas connection string
- `PG_*`: PostgreSQL credentials (Render-hosted)
- `SESSION_SECRET`: Session encryption key
- Password fields contain special characters; ensure they are URL-encoded in connection strings

### Database Initialization
All table creation functions run on startup:
- `createUsersTable()`: Users with authentication fields
- `createBookingsTable()`: Bookings with full details and status
- `createAdminTable()`: Admins with default admin/admin123 created if table is empty
- `createBookingStatusTable()`: Audit trail for booking status changes with indexes

### Key Implementation Details
- **Duplicate Route Issue** (line 224-225, 719-724): `/sign` route defined twice; the second definition (lines 719-724) is the correct one with authentication check
- **Duplicate `/profile` Route** (lines 671-685, 767-779): Profile route also appears twice; both are identical
- **Duplicate `/sign` POST Route** (lines 782-800): Posted twice with identical Passport auth config
- **Contact Form Validation**: Uses regex for email validation; requires all fields
- **Booking Status Defaults**: New bookings always created with `'pending'` status
- **Admin Creation**: Default admin (username: `admin`, password: `admin123`) created if admins table is empty

### Important Configuration
- Neon PostgreSQL always requires SSL (configured with `{ rejectUnauthorized: false }`)
- Session secret should be changed from default value in `.env`
- Passport serialization uses entire user object (consider limiting to user ID for security)

### File Organization
- `index.js`: All backend logic (table creation, routes, middleware, authentication)
- `views/`: EJS templates for all pages (no subdirectories)
- `public/`: Static assets (CSS, images, client-side JS)
- `tailwind.config.js`: Tailwind configuration (content path set to `./src/**/*.{html,js}` but actual views are in `./views`)

## Testing

No formal test suite is configured. Test route available:
```bash
GET /test              # Returns success JSON
DELETE /test-delete    # Returns success JSON for DELETE method testing
```

## Notes for Future Development

1. **Consolidate Routes**: Remove duplicate route definitions in `index.js`
2. **Security Hardening**: 
   - Change default admin credentials
   - Update Passport serialization to use user ID only
   - Consider password reset functionality
3. **Frontend Build**: Tailwind config references `./src/**/*.{html,js}` but views are in `./views/` - verify build process alignment
4. **Error Handling**: Many try-catch blocks redirect instead of providing structured error responses
5. **Database Indexes**: Consider adding indexes on frequently queried fields (user email, booking user_email)
