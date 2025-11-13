import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import session from "express-session";
import dotenv from "dotenv";
import mongoose from "mongoose";
import nodemailer from "nodemailer";

dotenv.config(); // Load variables from .env

const app = express();
const port = process.env.PORT || 3000;
const saltRounds = 10;

// Nodemailer transporter (uses Gmail by default). Set EMAIL_USER and EMAIL_PASSWORD in .env
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD,
  },
});

const sendEmail = async (to, subject, html) => {
  try {
    const info = await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to,
      subject,
      html,
    });
    console.log('Email sent:', info.response);
    return true;
  } catch (err) {
    console.error('Email send error:', err.message);
    return false;
  }
};

app.use(
    session({    
    secret: process.env.SESSION_SECRET,
      resave: false,
      saveUninitialized: true,
    //   cookie:{
    //     maxAge: 1000*60*60*24,
    //   },
      
    })
  );



app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static("public"));

app.use(passport.initialize());
app.use(passport.session());

// Use connection pool instead of single client
// Prefer DATABASE_URL if provided (e.g., Neon), otherwise use discrete env vars
const baseDbConfig = process.env.DATABASE_URL && process.env.DATABASE_URL.trim().length > 0
  ? {
      connectionString: process.env.DATABASE_URL,
      // Neon and many hosted PGs require SSL
      ssl: { rejectUnauthorized: false },
    }
  : {
      user: process.env.PG_USER,
      host: process.env.PG_HOST,
      database: process.env.PG_DATABASE,
      password: process.env.PG_PASSWORD,
      port: parseInt(process.env.PG_PORT || '5432', 10),
      ssl: { rejectUnauthorized: false },
    };

const db = new pg.Pool({
  ...baseDbConfig,
  // Keep this modest to avoid hosted DB connection limits (Neon free tiers often 3–10)
  max: parseInt(process.env.PG_POOL_MAX || '5', 10),
  idleTimeoutMillis: parseInt(process.env.PG_IDLE_TIMEOUT_MS || '30000', 10),
  connectionTimeoutMillis: parseInt(process.env.PG_CONN_TIMEOUT_MS || '30000', 10),
  keepAlive: true,
});

db.on('connect', () => console.log('PostgreSQL client connected'));
db.on('acquire', () => console.log('PostgreSQL client acquired from pool'));
db.on('remove', () => console.log('PostgreSQL client removed from pool'));
db.on('error', (err) => {
  console.error('Unexpected error on idle client', err);
});

// Lightweight connectivity probe
(db.query('SELECT 1'))
  .then(() => console.log("Connected to PostgreSQL"))
  .catch(err => {
    console.error("Connection error:", err);
    console.log("Retrying connection in 5 seconds...");
    setTimeout(() => {
      db.query('SELECT 1')
        .then(() => console.log("Reconnected to PostgreSQL"))
        .catch(err => console.error("Reconnection error:", err));
    }, 5000);
  });

// MongoDB connection
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/ridepartner_contacts';

mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => {
    console.log('Connected to MongoDB');
})
.catch((error) => {
    console.error('MongoDB connection error:', error);
});

// Contact Message Schema
const contactSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true
    },
    email: {
        type: String,
        required: true,
        trim: true,
        lowercase: true
    },
    phone: {
        type: String,
        required: true,
        trim: true
    },
    message: {
        type: String,
        required: true,
        trim: true
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    status: {
        type: String,
        enum: ['new', 'read', 'replied'],
        default: 'new'
    }
});

const Contact = mongoose.model('Contact', contactSchema);

// Create bookings table if it doesn't exist
const createBookingsTable = async () => {
    try {
        await db.query(`
            CREATE TABLE IF NOT EXISTS bookings (
                id SERIAL PRIMARY KEY,
                pickup_location VARCHAR(255) NOT NULL,
                destination VARCHAR(255) NOT NULL,
                booking_date DATE NOT NULL,
                booking_time TIME,
                passengers VARCHAR(10),
                vehicle_type VARCHAR(50),
                contact_phone VARCHAR(20),
                special_notes TEXT,
                user_email VARCHAR(255),
                user_name VARCHAR(255),
                user_phone VARCHAR(20),
                status VARCHAR(50) DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log("Bookings table created or already exists");
        
        // Add missing columns if they don't exist
        try {
            await db.query(`ALTER TABLE bookings ADD COLUMN IF NOT EXISTS booking_time TIME`);
            await db.query(`ALTER TABLE bookings ADD COLUMN IF NOT EXISTS passengers VARCHAR(10)`);
            await db.query(`ALTER TABLE bookings ADD COLUMN IF NOT EXISTS vehicle_type VARCHAR(50)`);
            await db.query(`ALTER TABLE bookings ADD COLUMN IF NOT EXISTS contact_phone VARCHAR(20)`);
            await db.query(`ALTER TABLE bookings ADD COLUMN IF NOT EXISTS special_notes TEXT`);
            await db.query(`ALTER TABLE bookings ADD COLUMN IF NOT EXISTS user_email VARCHAR(255)`);
            await db.query(`ALTER TABLE bookings ADD COLUMN IF NOT EXISTS user_name VARCHAR(255)`);
            await db.query(`ALTER TABLE bookings ADD COLUMN IF NOT EXISTS user_phone VARCHAR(20)`);
            await db.query(`ALTER TABLE bookings ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'pending'`);
            await db.query(`ALTER TABLE bookings ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP`);
            
        // Update existing bookings with NULL status to 'pending'
        await db.query(`UPDATE bookings SET status = 'pending' WHERE status IS NULL OR status = 'NULL'`);
        
        // Debug: Check current bookings and their status
        const debugResult = await db.query(`SELECT id, status, user_name FROM bookings ORDER BY id DESC LIMIT 5`);
        console.log("Current bookings in database:", debugResult.rows);
        
        console.log("Missing columns added to bookings table");
        } catch (alterErr) {
            console.log("Columns already exist or error adding columns:", alterErr.message);
        }
    } catch (err) {
        console.error("Error creating bookings table:", err);
    }
};

// Create admin table if it doesn't exist
const createAdminTable = async () => {
    try {
        await db.query(`
            CREATE TABLE IF NOT EXISTS admins (
                id SERIAL PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                full_name VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log("Admins table created or already exists");
        
        // Create default admin if no admins exist
        const adminCheck = await db.query("SELECT COUNT(*) FROM admins");
        if (parseInt(adminCheck.rows[0].count) === 0) {
            const hashedPassword = await bcrypt.hash("admin123", saltRounds);
            await db.query(
                "INSERT INTO admins (username, password, email, full_name) VALUES ($1, $2, $3, $4)",
                ["admin", hashedPassword, "admin@ridepartner.com", "System Administrator"]
            );
            console.log("Default admin created - Username: admin, Password: admin123");
        } else {
            console.log("Admins already exist in database");
        }
    } catch (err) {
        console.error("Error creating admins table:", err);
    }
};

// Create booking status history table
const createBookingStatusTable = async () => {
    try {
        await db.query(`
            CREATE TABLE IF NOT EXISTS booking_status_history (
                id SERIAL PRIMARY KEY,
                booking_id INTEGER REFERENCES bookings(id) ON DELETE CASCADE,
                previous_status VARCHAR(50),
                new_status VARCHAR(50) NOT NULL,
                changed_by VARCHAR(255),
                admin_id INTEGER REFERENCES admins(id),
                change_reason TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log("Booking status history table created or already exists");
        
        // Create index for better performance
        try {
            await db.query(`CREATE INDEX IF NOT EXISTS idx_booking_status_booking_id ON booking_status_history(booking_id)`);
            await db.query(`CREATE INDEX IF NOT EXISTS idx_booking_status_created_at ON booking_status_history(created_at)`);
            console.log("Indexes created for booking status history table");
        } catch (indexErr) {
            console.log("Indexes already exist or error creating indexes:", indexErr.message);
        }
    } catch (err) {
        console.error("Error creating booking status history table:", err);
    }
};

// Create join requests table
const createJoinRequestsTable = async () => {
    try {
        await db.query(`
            CREATE TABLE IF NOT EXISTS join_requests (
                id SERIAL PRIMARY KEY,
                booking_id INTEGER REFERENCES bookings(id) ON DELETE CASCADE,
                requester_email VARCHAR(255) NOT NULL,
                requester_name VARCHAR(255) NOT NULL,
                requester_phone VARCHAR(20),
                message TEXT,
                status VARCHAR(50) DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                response_at TIMESTAMP
            )
        `);
        console.log("Join requests table created or already exists");
    } catch (err) {
        console.error("Error creating join requests table:", err);
    }
};

app.get("/", (req, res) => {
    res.render("signup.ejs");
});

app.get("/sign", (req, res) => {
    res.render("sign.ejs");
});


app.get("/signup", (req, res) => {
    res.render("signup.ejs");
});

app.get("/index", (req, res) => {
    res.render("index.ejs");
});

app.get("/index5", (req, res) => {
    const booking = req.query.booking;
    res.render("index5.ejs", { booking });
});

app.get("/services", (req, res) => {
    const booking = req.query.booking;
    res.render("index5.ejs", { booking });
});

// Contact admin page
app.get("/contact-admin", (req, res) => {
    res.render("contact-admin.ejs");
});

// Test route to check if server is working
app.get("/test", (req, res) => {
    res.json({ success: true, message: "Server is working!" });
});

// Test DELETE route
app.delete("/test-delete", (req, res) => {
    res.json({ success: true, message: "DELETE method is working!" });
});

// Contact form submission route
app.post("/contact", async (req, res) => {
    try {
        const { name, email, phone, message } = req.body;
        
        // Debug logging
        console.log('=== CONTACT FORM SUBMISSION ===');
        console.log('Received contact form data:', { name, email, phone, message });
        console.log('Request body:', req.body);
        console.log('Request headers:', req.headers);

        // Validation
        if (!name || !email || !phone || !message) {
            console.log('Validation failed - missing fields:', { 
                hasName: !!name, 
                hasEmail: !!email, 
                hasPhone: !!phone, 
                hasMessage: !!message 
            });
            return res.status(400).json({
                success: false,
                message: 'All fields are required'
            });
        }

        // Email validation
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({
                success: false,
                message: 'Please enter a valid email address'
            });
        }

        // Create new contact message
        const contactMessage = new Contact({
            name: name.trim(),
            email: email.trim().toLowerCase(),
            phone: phone.trim(),
            message: message.trim()
        });

        // Save to database
        await contactMessage.save();

        console.log('New contact message received:', {
            name: contactMessage.name,
            email: contactMessage.email,
            phone: contactMessage.phone,
            message: contactMessage.message.substring(0, 50) + '...',
            createdAt: contactMessage.createdAt
        });

        // Send success response
        res.json({
            success: true,
            message: 'Thank you for your message! We will get back to you soon.',
            data: {
                id: contactMessage._id,
                name: contactMessage.name,
                email: contactMessage.email,
                createdAt: contactMessage.createdAt
            }
        });

    } catch (error) {
        console.error('Error saving contact message:', error);
        res.status(500).json({
            success: false,
            message: 'Sorry, there was an error sending your message. Please try again later.'
        });
    }
});

// Get all contact messages (for admin purposes)
app.get("/api/contacts", async (req, res) => {
    try {
        const contacts = await Contact.find()
            .sort({ createdAt: -1 })
            .select('name email phone message createdAt status');

        res.json({
            success: true,
            data: contacts
        });
    } catch (error) {
        console.error('Error fetching contacts:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching contact messages'
        });
    }
});

// Delete a contact message
app.delete("/api/contacts/:id", async (req, res) => {
    try {
        console.log('=== DELETE CONTACT MESSAGE ===');
        console.log('Delete request received for ID:', req.params.id);
        console.log('Request method:', req.method);
        console.log('Request URL:', req.url);
        
        const { id } = req.params;
        
        // Check if message exists
        const message = await Contact.findById(id);
        if (!message) {
            console.log('Message not found with ID:', id);
            return res.status(404).json({
                success: false,
                message: 'Message not found'
            });
        }
        
        // Delete the message
        await Contact.findByIdAndDelete(id);
        
        console.log(`Contact message deleted: ${message.name} - ${message.email}`);
        
        res.json({
            success: true,
            message: 'Message deleted successfully'
        });
    } catch (error) {
        console.error('Error deleting contact message:', error);
        res.status(500).json({
            success: false,
            message: 'Error deleting message'
        });
    }
});


app.get("/logout", (req, res) => {
    res.redirect("sign");
});

// Booking route handler
app.post("/book", async (req, res) => {
    const { 
        pickup, 
        destination, 
        date, 
        time, 
        passengers, 
        vehicle, 
        phone, 
        notes,
        email,
        name
    } = req.body;
    
    // Use logged-in user data if available, otherwise use form data
    const userEmail = req.user ? req.user.email : email;
    const userName = req.user ? req.user.name1 : name;
    const userPhone = req.user ? req.user.phone_number : phone;
    
    try {
        // Insert booking into database with new fields
        const result = await db.query(
            `INSERT INTO bookings (
                pickup_location, 
                destination, 
                booking_date, 
                booking_time,
                passengers,
                vehicle_type,
                contact_phone,
                special_notes,
                user_email, 
                user_name, 
                user_phone, 
                status, 
                created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW()) RETURNING id`,
            [
                pickup, 
                destination, 
                date, 
                time,
                passengers,
                vehicle,
                phone,
                notes,
                userEmail, 
                userName, 
                userPhone, 
                'pending'
            ]
        );
        
        const bookingId = result.rows[0].id;
        
        console.log(`New booking request received:
        - From: ${pickup}
        - To: ${destination}
        - Date: ${date} at ${time}
        - Passengers: ${passengers}
        - Vehicle: ${vehicle}
        - Contact: ${userPhone}
        - Notes: ${notes}
        - User: ${userName} (${userEmail})
        - Status: pending`);
        
        // Log initial status in history table
        await db.query(
            `INSERT INTO booking_status_history (booking_id, previous_status, new_status, changed_by, change_reason) 
             VALUES ($1, NULL, 'pending', 'system', 'Initial booking created')`,
            [bookingId]
        );
        
        // Redirect to confirmation page or back to services with success message
        res.redirect("/services?booking=success");
        
    } catch (err) {
        console.error("Error creating booking:", err);
        res.redirect("/services?booking=error");
    }
});

// Get all available bookings (only pending status, exclude current user's own bookings)
app.get("/api/bookings", async (req, res) => {
    const userEmail = (req.user && req.user.email) ? req.user.email : (req.query.email || null);
    try {
        let query = `
            SELECT 
                id, 
                pickup_location, 
                destination, 
                booking_date, 
                booking_time, 
                passengers, 
                vehicle_type, 
                user_name, 
                user_email, 
                user_phone,
                special_notes,
                status,
                created_at
            FROM bookings 
            WHERE status = 'pending'`;
        const params = [];
        if (userEmail) {
            query += " AND user_email <> $1";
            params.push(userEmail);
        }
        query += " ORDER BY booking_date DESC, booking_time DESC";

        const result = await db.query(query, params);
        
        res.json({
            success: true,
            data: result.rows
        });
    } catch (err) {
        console.error("Error fetching bookings:", err);
        res.status(500).json({
            success: false,
            message: "Error fetching bookings"
        });
    }
});

// Submit a join request
app.post("/api/join-request", async (req, res) => {
    const { booking_id, requester_email, requester_name, requester_phone, message } = req.body;
    
    try {
        // Get booking details
        const bookingResult = await db.query("SELECT * FROM bookings WHERE id = $1", [booking_id]);
        
        if (bookingResult.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: "Booking not found"
            });
        }
        
        const booking = bookingResult.rows[0];
        
        // Insert join request
        await db.query(
            `INSERT INTO join_requests (booking_id, requester_email, requester_name, requester_phone, message, status) 
             VALUES ($1, $2, $3, $4, $5, 'pending')`,
            [booking_id, requester_email, requester_name, requester_phone, message]
        );
        
        console.log(`Join request submitted: ${requester_name} wants to join booking #${booking_id}`);
        console.log(`Owner will be notified: ${booking.user_email}`);
        console.log(`Requester email: ${requester_email}`);
        console.log(`Requester phone: ${requester_phone}`);
        
        res.json({
            success: true,
            message: "Join request submitted successfully",
            data: {
                booking_id,
                booking_owner: booking.user_name,
                booking_owner_email: booking.user_email
            }
        });
        
    } catch (err) {
        console.error("Error creating join request:", err);
        res.status(500).json({
            success: false,
            message: "Error submitting join request"
        });
    }
});

// Get user's bookings with join requests
app.get("/api/my-bookings", async (req, res) => {
    const { email } = req.query;
    
    if (!email) {
        return res.status(400).json({
            success: false,
            message: "Email required"
        });
    }
    
    try {
        const result = await db.query(`
            SELECT 
                b.id,
                b.pickup_location,
                b.destination,
                b.booking_date,
                b.booking_time,
                b.passengers,
                b.vehicle_type,
                b.user_name,
                b.user_email,
                b.user_phone,
                b.special_notes,
                b.status,
                b.created_at,
                json_agg(json_build_object(
                    'id', jr.id,
                    'requester_name', jr.requester_name,
                    'requester_email', jr.requester_email,
                    'requester_phone', jr.requester_phone,
                    'message', jr.message,
                    'status', jr.status,
                    'created_at', jr.created_at
                )) FILTER (WHERE jr.id IS NOT NULL) as join_requests
            FROM bookings b
            LEFT JOIN join_requests jr ON b.id = jr.booking_id
            WHERE b.user_email = $1
            GROUP BY b.id
            ORDER BY b.booking_date DESC
        `, [email]);
        
        res.json({
            success: true,
            data: result.rows
        });
    } catch (err) {
        console.error("Error fetching user bookings:", err);
        res.status(500).json({
            success: false,
            message: "Error fetching bookings"
        });
    }
});

// Get join requests for user (by email)
app.get("/api/my-join-requests", async (req, res) => {
    const { email } = req.query;
    
    if (!email) {
        return res.status(400).json({
            success: false,
            message: "Email required"
        });
    }
    
    try {
        const result = await db.query(`
            SELECT 
                jr.id,
                jr.booking_id,
                jr.requester_email,
                jr.requester_name,
                jr.requester_phone,
                jr.message,
                jr.status,
                jr.created_at,
                b.pickup_location,
                b.destination,
                b.booking_date,
                b.booking_time
            FROM join_requests jr
            JOIN bookings b ON jr.booking_id = b.id
            WHERE b.user_email = $1
            ORDER BY jr.created_at DESC
        `, [email]);
        
        res.json({
            success: true,
            data: result.rows
        });
    } catch (err) {
        console.error("Error fetching join requests:", err);
        res.status(500).json({
            success: false,
            message: "Error fetching join requests"
        });
    }
});

// Update join request status
app.post("/api/join-request-response", async (req, res) => {
    const { request_id, status } = req.body;
    
    if (!['accepted', 'rejected'].includes(status)) {
        return res.status(400).json({
            success: false,
            message: "Invalid status"
        });
    }
    
    try {
        // Get the join request and booking info
        const joinRequestResult = await db.query(
            `SELECT jr.*, b.id as booking_id FROM join_requests jr 
             JOIN bookings b ON jr.booking_id = b.id WHERE jr.id = $1`,
            [request_id]
        );
        
        if (joinRequestResult.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: "Join request not found"
            });
        }
        
        const booking_id = joinRequestResult.rows[0].booking_id;
        
        // Update join request status
        await db.query(
            `UPDATE join_requests SET status = $1, response_at = NOW() WHERE id = $2`,
            [status, request_id]
        );
        
        // If accepted, update booking status to 'accepted' (removes from available bookings)
        if (status === 'accepted') {
            await db.query(
                `UPDATE bookings SET status = 'accepted', updated_at = NOW() WHERE id = $1`,
                [booking_id]
            );
            console.log(`Booking #${booking_id} marked as accepted - will no longer appear in available bookings`);
        }
        
        res.json({
            success: true,
            message: `Join request ${status} successfully`,
            booking_id
        });
    } catch (err) {
        console.error("Error updating join request:", err);
        res.status(500).json({
            success: false,
            message: "Error updating join request"
        });
    }
});

// Admin login POST route - REMOVED
// This route no longer exists
app.post("/admin-login", async (req, res) => {
    const { username, password } = req.body;
    
    try {
        const result = await db.query("SELECT * FROM admins WHERE username = $1", [username]);
        
        if (result.rows.length > 0) {
            const admin = result.rows[0];
            const validPassword = await bcrypt.compare(password, admin.password);
            
            if (validPassword) {
                // Add role to admin object for session
                admin.role = 'admin';
                req.login(admin, (err) => {
                    if (err) {
                        console.error("Error during admin login:", err);
                        return res.redirect("/admin-login?error=login_failed");
                    }
                    return res.redirect("/admin");
                });
            } else {
                res.redirect("/admin-login?error=invalid_credentials");
            }
        } else {
            res.redirect("/admin-login?error=invalid_credentials");
        }
    } catch (err) {
        console.error("Error during admin login:", err);
        res.redirect("/admin-login?error=server_error");
    }
});

// Route to view all bookings (for admin only)
app.get("/bookings", async (req, res) => {
    if (!req.isAuthenticated() || req.user.role !== 'admin') {
        return res.status(401).json({ error: "Unauthorized" });
    }
    
    try {
        const result = await db.query("SELECT * FROM bookings ORDER BY created_at DESC");
        console.log("Bookings fetched from database:", result.rows.map(booking => ({
            id: booking.id,
            status: booking.status,
            user_name: booking.user_name
        })));
        res.json(result.rows);
    } catch (err) {
        console.error("Error fetching bookings:", err);
        res.status(500).json({ error: "Failed to fetch bookings" });
    }
});

// Route to get booking status history (for admin only)
app.get("/booking-history/:id", async (req, res) => {
    if (!req.isAuthenticated() || req.user.role !== 'admin') {
        return res.status(401).json({ error: "Unauthorized" });
    }
    
    const { id } = req.params;
    
    try {
        const result = await db.query(`
            SELECT 
                bsh.*,
                a.username as admin_username,
                a.full_name as admin_name
            FROM booking_status_history bsh
            LEFT JOIN admins a ON bsh.admin_id = a.id
            WHERE bsh.booking_id = $1
            ORDER BY bsh.created_at DESC
        `, [id]);
        
        res.json(result.rows);
    } catch (err) {
        console.error("Error fetching booking history:", err);
        res.status(500).json({ error: "Failed to fetch booking history" });
    }
});

// Route to update booking status (for admin only)
app.post("/update-booking/:id", async (req, res) => {
    if (!req.isAuthenticated() || req.user.role !== 'admin') {
        return res.status(401).json({ error: "Unauthorized" });
    }
    
    const { id } = req.params;
    const { status, reason } = req.body;
    
    // Debug logging
    console.log("Update booking request:", { id, status, reason, body: req.body });
    
    // Validate status parameter
    if (!status) {
        console.error("Status parameter is missing or null");
        return res.status(400).json({ error: "Status parameter is required" });
    }
    
    try {
        // Check if booking exists and get current status
        const currentBooking = await db.query("SELECT id, status FROM bookings WHERE id = $1", [id]);
        if (currentBooking.rows.length === 0) {
            return res.status(404).json({ error: "Booking not found" });
        }
        
        const previousStatus = currentBooking.rows[0].status;
        
        // Update booking status in database
        await db.query(
            "UPDATE bookings SET status = $1, updated_at = NOW() WHERE id = $2",
            [status, id]
        );
        
        // Log status change in history table
        await db.query(
            `INSERT INTO booking_status_history (booking_id, previous_status, new_status, changed_by, admin_id, change_reason) 
             VALUES ($1, $2, $3, $4, $5, $6)`,
            [id, previousStatus, status, req.user.username, req.user.id, 'Status updated by admin']
        );
        
        console.log(`Booking #${id} status updated from "${previousStatus}" to "${status}" by admin ${req.user.username}`);
        
        res.json({ success: true });
    } catch (err) {
        console.error("Error updating booking:", err);
        res.status(500).json({ error: "Failed to update booking" });
    }
});





// View all available bookings
app.get("/view-bookings", (req, res) => {
    if (req.isAuthenticated()) {
        res.render("view-bookings.ejs", { user: req.user });
    } else {
        res.redirect("/sign");
    }
});

// View my bookings and manage join requests
app.get("/my-bookings", (req, res) => {
    if (req.isAuthenticated()) {
        res.render("my-bookings.ejs", { user: req.user });
    } else {
        res.redirect("/sign");
    }
});

// View my join requests
app.get("/my-requests", (req, res) => {
    if (req.isAuthenticated()) {
        res.render("my-requests.ejs", { user: req.user });
    } else {
        res.redirect("/sign");
    }
});

// Get user's join requests
app.get("/api/my-requests", async (req, res) => {
    const { email } = req.query;
    
    if (!email) {
        return res.status(400).json({
            success: false,
            message: "Email required"
        });
    }
    
    try {
        const result = await db.query(`
            SELECT 
                jr.id,
                jr.booking_id,
                jr.requester_email,
                jr.requester_name,
                jr.requester_phone,
                jr.message,
                jr.status,
                jr.created_at,
                jr.response_at,
                b.pickup_location,
                b.destination,
                b.booking_date,
                b.booking_time,
                b.user_name,
                b.user_phone
            FROM join_requests jr
            JOIN bookings b ON jr.booking_id = b.id
            WHERE jr.requester_email = $1
            ORDER BY jr.created_at DESC
        `, [email]);
        
        res.json({
            success: true,
            data: result.rows
        });
    } catch (err) {
        console.error("Error fetching user requests:", err);
        res.status(500).json({
            success: false,
            message: "Error fetching requests"
        });
    }
});

app.get("/profile", (req, res) => {
    // console.log(req.user);
    if (req.isAuthenticated()) {
      res.render("profile.ejs",{
        name: req.user.name1,
        email: req.user.email,
        phone_number: req.user.phone_number,
        gender: req.user.gender,
        your_date_column: req.user.your_date_column
      }
    );
    } else {
      res.redirect("/sign");
    }
  });
  // Add this function with your other table creation functions:

// Create users table if it doesn't exist
const createUsersTable = async () => {
    try {
        await db.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                name1 VARCHAR(255),
                phone_number VARCHAR(20),
                gender VARCHAR(50),
                your_date_column VARCHAR(10),
                secret TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log("Users table created or already exists");
    } catch (err) {
        console.error("Error creating users table:", err);
    }
};

// Configure Passport strategy first
passport.use(
    new Strategy(async function verify(username, password, cb) {
      try {
        const result = await db.query("SELECT * FROM users WHERE email = $1 ", [
          username,
        ]);
        if (result.rows.length > 0) {
          const user = result.rows[0];
          const storedHashedPassword = user.password;
          bcrypt.compare(password, storedHashedPassword, (err, valid) => {
            if (err) {
              console.error("Error comparing passwords:", err);
              return cb(err);
            } else {
              if (valid) {
                return cb(null, user);
              } else {
                return cb(null, false);
              }
            }
          });
        } else {
          return cb("User not found");
        }
      } catch (err) {
        console.log(err);
      }
    })
);

passport.serializeUser((user, cb) => {
    cb(null, user);
});
passport.deserializeUser((user, cb) => {
    cb(null, user);
});

// ===== ROUTES =====

app.get("/sign", (req, res) => {
    if (req.isAuthenticated()) {
        return res.redirect("/profile");
    }
    res.render("sign.ejs");
});

app.post(
    "/sign",
    passport.authenticate("local", {
        successRedirect: "/profile",
        failureRedirect: "/sign",
    })
);

app.post("/signup", async (req, res) => {
    const email = req.body.username;
    const password = req.body.password;
    const name1 = req.body.givenName;
    const phone_number = req.body.contactNumber;
    const gender = req.body.gender;
    const your_date_column = req.body.yob;

    try {
        const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [email]);
  
        if (checkResult.rows.length > 0) {
            return res.redirect("/signup?error=email_exists");
        }
        
        const hash = await bcrypt.hash(password, saltRounds);
        const result = await db.query(
            "INSERT INTO users (email, password, name1, phone_number, gender, your_date_column) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *",
            [email, hash, name1, phone_number, gender, your_date_column]
        );
        
        const user = result.rows[0];
        
        req.login(user, (err) => {
            if (err) {
                console.error("Error during login after signup:", err);
                return res.redirect("/signup?error=login_failed");
            }
            console.log("User signed up and logged in:", user.email);
            return res.redirect("/profile");
        });
        
    } catch (err) {
        console.error("Signup error:", err);
        res.redirect("/signup?error=server_error");
    }
});

app.get("/profile", (req, res) => {
    if (req.isAuthenticated()) {
        res.render("profile.ejs", {
            name: req.user.name1,
            email: req.user.email,
            phone_number: req.user.phone_number,
            gender: req.user.gender,
            your_date_column: req.user.your_date_column
        });
    } else {
        res.redirect("/sign");
    }
});

// Initialize tables and start server
(async () => {
    try {
        // Wait for connection pool to establish
        console.log("Waiting for database connection pool to establish...");
        await new Promise(resolve => setTimeout(resolve, 3000));
        
        await createBookingsTable();
        await createAdminTable();
        await createBookingStatusTable();
        await createUsersTable();
        await createJoinRequestsTable();
        console.log("All tables initialized successfully");
        
        // Start server after tables are initialized
        app.listen(port, () => {
            console.log(`Server running on port ${port}`);
        });
    } catch (err) {
        console.error("Error initializing tables:", err);
        // Don't exit - let server start anyway
        app.listen(port, () => {
            console.log(`Server running on port ${port} (tables initialization deferred)`);
        });
    }
})();

