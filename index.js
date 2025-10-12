import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import session from "express-session";
import dotenv from "dotenv";
import mongoose from "mongoose";

dotenv.config(); // Load variables from .env

const app = express();
const port = 5432;
const saltRounds = 10;

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

const isRender = process.env.PG_HOST && process.env.PG_HOST.includes("render");

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
  ssl: isRender ? { rejectUnauthorized: false } : false,
});

db.connect()
  .then(() => console.log("Connected to PostgreSQL"))
  .catch(err => console.error("Connection error:", err));

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

createBookingsTable();
createAdminTable();
createBookingStatusTable();

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

// Admin signup page
app.get("/admin-signup", (req, res) => {
    res.render("admin-signup.ejs");
});

// Admin login page
app.get("/admin-login", (req, res) => {
    res.render("admin-login.ejs");
});

// Admin dashboard (protected)
app.get("/admin", (req, res) => {
    if (req.isAuthenticated() && req.user.role === 'admin') {
        res.render("admin.ejs", { user: req.user });
    } else {
        res.redirect("/admin-login");
    }
});

// Admin logout
app.get("/admin-logout", (req, res) => {
    req.logout((err) => {
        if (err) {
            console.error("Error during logout:", err);
        }
        res.redirect("/admin-login");
    });
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

// Admin signup POST route
app.post("/admin-signup", async (req, res) => {
    const { username, email, password, fullName } = req.body;
    
    try {
        // Check if admin already exists
        const checkResult = await db.query("SELECT * FROM admins WHERE username = $1 OR email = $2", [username, email]);
        
        if (checkResult.rows.length > 0) {
            return res.redirect("/admin-signup?error=admin_exists");
        }
        
        // Hash password and create admin
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        await db.query(
            "INSERT INTO admins (username, password, email, full_name) VALUES ($1, $2, $3, $4)",
            [username, hashedPassword, email, fullName]
        );
        
        console.log(`New admin created: ${username} (${email})`);
        res.redirect("/admin-login?success=admin_created");
        
    } catch (err) {
        console.error("Error creating admin:", err);
        res.redirect("/admin-signup?error=server_error");
    }
});

// Admin login POST route
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
  app.get("/sign", async (req, res) => {
    console.log(req.user);
  
    ////////////////UPDATED GET SECRETS ROUTE/////////////////
    if (req.isAuthenticated()) {
      try {
        const result = await db.query(
          `SELECT secret FROM users WHERE email = $1`,
          [req.user.email]
        );
        console.log(result);
        const secret = result.rows[0].secret;
        if (secret) {
          res.render("profile.ejs", {   name: name1,
            email: email,
            phone_number: phone_number,
            gender: gender,
            your_date_column: your_date_column, });
        } else {
          res.render("profile.ejs");
        }
      } catch (err) {
        console.log(err);
      }
    } else {
      res.redirect("/sign");
    }
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
            res.send("Email already exists. Try logging in.");
        } else {
            bcrypt.hash(password, saltRounds, async (err, hash) => {
                if (err) {
                    console.error("Error hashing password:", err);
                } else {
                    await db.query(
                        "INSERT INTO users (email, password,name1,phone_number,gender,your_date_column) VALUES ($1, $2,$3,$4,$5,$6)",
                        [email, hash,name1,phone_number,gender,your_date_column]
                    );
                    res.render("profile.ejs", {
                        name: name1,
                        email: email,
                        phone_number: phone_number,
                        gender: gender,
                        your_date_column: your_date_column,
                    });
                }
            });
        }
    } catch (err) {
        console.log(err);
    }
});


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
                  //Error with password check
                  console.error("Error comparing passwords:", err);
                  return cb(err);
                } else {
                  if (valid) {
                    //Passed password check
                    return cb(null, user);
                  } else {
                    //Did not pass password check
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

  app.listen(port, () => {
    console.log(`Server running on port ${port}`);
  });

