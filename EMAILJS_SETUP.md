# EmailJS Setup Guide

This document explains how to set up EmailJS to send join request emails in the Ride Partner application.

## What is EmailJS?

EmailJS is a free service that allows you to send emails directly from your frontend JavaScript code without needing a backend email server. Perfect for our use case!

## Step 1: Create EmailJS Account

1. Go to [EmailJS.com](https://www.emailjs.com/)
2. Click "Sign Up Free"
3. Create an account (or sign in with Google)
4. Verify your email

## Step 2: Add an Email Service

1. Go to **Email Services** in the dashboard
2. Click **Add New Service**
3. Choose your email provider:
   - **Gmail** (recommended for testing)
   - **Outlook**
   - **Other SMTP services**

### For Gmail:
1. Select Gmail
2. Connect your Gmail account
3. Follow the authorization steps
4. Note the **Service ID** (e.g., `service_abc123`)

## Step 3: Create an Email Template

1. Go to **Email Templates** in the dashboard
2. Click **Create New Template**
3. Set up your template with these variables:
   ```
   Subject: New Ride Join Request - {{ride_route}}
   
   From: {{from_name}} <{{from_email}}>
   
   Body:
   Hello {{to_name}},
   
   {{from_name}} ({{from_email}}) would like to join your ride!
   
   **Ride Details:**
   Route: {{ride_route}}
   Date: {{ride_date}}
   Time: {{ride_time}}
   
   **Requester Details:**
   Name: {{from_name}}
   Email: {{from_email}}
   Phone: {{requester_phone}}
   
   **Message:**
   {{message}}
   
   Please contact them to confirm.
   
   Best regards,
   Ride Partner Team
   ```

4. Note the **Template ID** (e.g., `template_abc123`)

## Step 4: Get Your API Keys

1. Go to **Account** or **Integration** settings
2. Find your **Public Key** (starts with numbers, safe to expose in frontend)
3. Copy your **Public Key**

## Step 5: Update the Code

In `views/view-bookings.ejs`, replace these lines:

```javascript
// Line 130:
emailjs.init("YOUR_EMAILJS_PUBLIC_KEY");

// Line 245:
emailjs.send("YOUR_SERVICE_ID", "YOUR_TEMPLATE_ID", {
```

With your actual values:

```javascript
// Line 130:
emailjs.init("abc123def456ghi789"); // Your Public Key

// Line 245:
emailjs.send("service_abc123xyz", "template_abc123xyz", {
```

## Step 6: Test It Out

1. Restart your server: `npm start`
2. Log in to your app
3. Go to **View Bookings**
4. Click **Request to Join** on any booking
5. Fill in the form and submit
6. Check your email to see if you received the notification!

## Troubleshooting

### Emails not sending?
- Check EmailJS dashboard for error logs
- Verify Service ID and Template ID are correct
- Ensure Public Key is correct
- Check if the Gmail account has "Less secure app access" enabled (for Gmail)

### Template variables not showing?
- Make sure variable names in code match template exactly (case-sensitive)
- Variables must be wrapped in `{{variable_name}}`

### Getting CORS errors?
- EmailJS should handle CORS automatically
- Clear browser cache and try again
- Make sure you're using the Public Key, not Private Key

## Production Considerations

- Keep your Public Key in the code (it's safe - it's public)
- Never expose your Private Key in frontend code
- EmailJS has free tier with 200 emails/month
- For higher volume, consider upgrading EmailJS plan

## Features Implemented

✅ Users can view all available bookings  
✅ Users can send join requests with a message  
✅ Join request is saved to database  
✅ Email is sent to ride owner with join request details  
✅ Ride owner receives email with requester's contact info  

## Database Schema

The `join_requests` table stores:
- `id`: Unique request ID
- `booking_id`: Which booking this request is for
- `requester_email`: Email of person requesting to join
- `requester_name`: Name of person requesting to join
- `requester_phone`: Phone number of requester
- `message`: Optional message from requester
- `status`: pending/accepted/rejected
- `created_at`: When request was made
- `response_at`: When owner responded

## Next Steps

You could enhance this further by:
1. Creating a "My Join Requests" page to view responses
2. Allowing ride owners to accept/reject requests
3. Sending confirmation emails when requests are accepted
4. Rating system after completing a ride together
5. Chat feature between riders
