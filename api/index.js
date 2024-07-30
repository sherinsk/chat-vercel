const express = require('express');
const http = require('http');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Server } = require('socket.io');
const { PrismaClient } = require('@prisma/client');
const multer = require('multer');
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
const nodemailer = require("nodemailer");
const path = require('path');
const ejs = require('ejs');
const { error } = require('console');
const sharp = require('sharp');
const { decode } = require('punycode');


const prisma = new PrismaClient();
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: ["https://chat-frontend-ashen.vercel.app", "http://localhost:5173"], // Added localhost
    methods: ["GET", "POST"]
  }
});

const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 465,
  secure: true,
  auth: {
    user: "sherinsk.backenddev@gmail.com",
    pass: "gphl ubcb xolk btwt",
  },
});

function isEmail(email) {
  var emailFormat = /^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$/;
  if (email !== '' && email.match(emailFormat)) { return true; }
  
  return false;
}

function generateOTP() {
  return Math.floor(1000 + Math.random() * 9000); 
}

var emailwithOTP =[]


const JWT_SECRET = 'sherin'; // Replace with your secret

app.use(cors());
app.use(express.json());

const parseJwt = (token) => {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (e) {
    console.error('Invalid token', e);
    return null;
  }
};

2  // Global object to store user ID to socket ID mappings
const userSocketMap = new Map();

//send otp

const s3Client = new S3Client({
  region: process.env.AWS_REGION,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
  }
});

// Set up Multer storage
const storage = multer.memoryStorage();
const upload = multer({
  storage: storage,
  fileFilter: (req, file, cb) => {
    // Allow only JPEG files
    if (!file.mimetype.includes('jpeg' || 'png' ||'jpg')) {
      return cb(new Error('Only JPEG and PNG files are allowed'), false);
    }
    cb(null, true);
  }
});

const compressImage = async (buffer, maxSize) => {
  let quality = 80;
  let width = 800;
  let compressedBuffer = buffer;
  
  while (true) {
    const resizedBuffer = await sharp(compressedBuffer)
      .resize({ width }) // Resize to maintain aspect ratio
      .jpeg({ quality }) // Adjust JPEG quality
      .toBuffer();

    if (resizedBuffer.length <= maxSize || quality <= 10) {
      return resizedBuffer;
    }
    
    quality -= 10;
    if (quality < 10) quality = 10; // Minimum quality limit
  }
};

// Upload endpoint
app.patch('/upload', upload.single('image'), async (req, res) => {
  const file = req.file;
  var token=req.headers['authorization']
  token=token.split(' ')[1]
  console.log(token)
  const decoded=parseJwt(token)
  console.log(decoded)

  if (!file) {
    return res.status(400).json({ error: 'No file uploaded or file is too large.' });
  }

  let compressedImageBuffer = file.buffer;

  // Compress image if file size is greater than 200 KB
  if (file.size > 200 * 1024) {
    try {
      compressedImageBuffer = await compressImage(file.buffer, 200 * 1024);
    } catch (error) {
      console.error('Error compressing image:', error);
      return res.status(500).json({ error: 'Error compressing image' });
    }
  }

  const userFolder = `${decoded.userId}/`; // Create a folder named user-{userId}
  const photo = {
    Bucket: process.env.AWS_S3_BUCKET_NAME,
    Key: `${userFolder}${Date.now().toString()}-${file.originalname}`,
    Body: compressedImageBuffer,
    ContentType: 'image/jpeg'
  };

  photo.path = `https://${process.env.AWS_S3_BUCKET_NAME}.s3.${process.env.AWS_REGION}.amazonaws.com/${photo.Key}`;
  

  try {
    const command = new PutObjectCommand(photo);
    await s3Client.send(command);
    const photo_update=await prisma.user.update({where:{id:parseInt(decoded.userId)},data:{profilePic:photo.path}})
    res.status(200).json({ message: 'File uploaded successfully', imageUrl: photo.path });
  } catch (error) {
    console.error('Error uploading file:', error);
    res.status(500).json({ error: 'Error uploading file' });
  }
});

app.post('/sendotp',async (req, res)=>{
  const { email,username } = req.body;
   let generatedOTP={}
   generatedOTP.OTP = generateOTP()
   generatedOTP.email=email;
  if (!email) {
    return res.status(400).json({ error: "Email address is required." });
  }

  const emailValid=isEmail(email)
  if(!emailValid)
  {
    return res.status(200).json({status:false,message:"Invalid email Format"})
  }

  const existingUser=await prisma.user.findFirst({where:{email}})
    if(existingUser)
    {
      return res.status(200).json({status:false,message:"User already exists"})
    }
  console.log("Sending OTP to:", email);
  
  try {
    const html = await ejs.renderFile(path.join(__dirname, '..', 'views', 'otpEmail.ejs'), { otp: generatedOTP.OTP, username });

    const info = await transporter.sendMail({
      from: "sherinsk.backenddev@gmail.com",
      to: email,
      subject: "ChatWave-Registration OTP!!!",
      html: html,
    });

    emailwithOTP.push(generatedOTP)

    console.log("OTP sent: %s to %s", generatedOTP, email);
    res.status(200).json({ status:true,message: `OTP sent to ${email}` });

    setTimeout(() => {
      const index = emailwithOTP.findIndex(item => item.email === email);
      if (index !== -1) {
          emailwithOTP.splice(index, 1);
          console.log(`OTP removed for email ${email} after 60 seconds.`);
      }
  }, 60000);
  
  } catch (error) {
    console.error("Error sending OTP:", error);
    res.status(500).json({ error: "Failed to send OTP" });
  }
})

// Register user
app.post('/register', async (req, res) => {
  const { email, password, username } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  try {
    const user = await prisma.user.create({
      data: { email, password: hashedPassword, username,isEmailverified:true },
    });
    res.status(200).json({message:"User registered successfully"});
  } catch (error) {
    console.log(error);
    res.status(400).json('User already exists');
  }
});

app.post('/appregister', async (req, res) => {
  const { email, password, username,otp } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  try {
    const matchingEntry = emailwithOTP.find(entry => entry.email === email && entry.OTP == otp);

      if (!matchingEntry) {
          return res.status(200).json({ status:false, message: "Invalid OTP" });
      }

      // If found, remove the entry from the array
      const index = emailwithOTP.indexOf(matchingEntry);
      emailwithOTP.splice(index, 1);
    const user = await prisma.user.create({
      data: { email, password: hashedPassword, username,isEmailverified:true },
    });
    res.status(200).json({status:true,message:"User registered successfully"});
  } catch (error) {
    console.log(error);
    res.status(500).json({error:"Internal server Error"});
  }
});

// Login user
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try
  {
    const user = await prisma.user.findUnique({ where: { email } });
    if (user && await bcrypt.compare(password, user.password)) {
      const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '24h' });
      res.status(200).json({status:true, token,userId:user.id });
    } else {
      res.status(200).json({status:false,message:'Invalid credentials'});
    }
  }
  catch(err)
  {
    console.log(err)
    res.status(500).json({error:"Internal Server Error"})
  }
});

// Middleware to authenticate token
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.userId = user.userId;
    next();
  });
};

// Get all users
app.get('/users', async (req, res) => {
  try {
    const users = await prisma.user.findMany();
    let token = req.headers['authorization'];
    token = token.split(' ')[1];
    const tokenUserId = (parseJwt(token)).userId;

    for (let i = 0; i < users.length; i++) {
      const userId = users[i].id;
      const messages = await prisma.message.findMany({
        where: {
          OR: [
            { senderId: parseInt(tokenUserId), receiverId: parseInt(userId) },
            { senderId: parseInt(userId), receiverId: parseInt(tokenUserId) },
          ],
        },
        orderBy: {
          createdAt: 'desc',
        },
        take: 1,
      });

      if (messages.length > 0) {
        const lastMessage = messages[0];
        users[i].lastMessage = {
          message: lastMessage.content,
          timestamp: lastMessage.createdAt,
          type: lastMessage.senderId === parseInt(tokenUserId) ? 'Sent' : 'Received',
        };
      } else {
        users[i].lastMessage = null;
      }
    }

    res.status(200).json(users);
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});


// Get user by id
app.get('/users/:id', async (req, res) => {
  const { id } = req.params;
  const user = await prisma.user.findUnique({ where: { id: parseInt(id) } });
  res.json(user);
});

// Get messages between two users
app.get('/messages/:receiverId', async (req, res) => {
  const { receiverId } = req.params;
  var token=req.headers['authorization']
  token=token.split(' ')[1]
  console.log(token)
  const senderId=(parseJwt(token)).userId

  const messages = await prisma.message.findMany({
    where: {
      OR: [
        { senderId: parseInt(senderId), receiverId: parseInt(receiverId) },
        { senderId: parseInt(receiverId), receiverId: parseInt(senderId) },
      ],
    },
    orderBy: {
      createdAt: 'asc',
    },
  });

  res.status(200).json({senderId,messages});
});

app.get('/messages/:senderId/:receiverId', async (req, res) => {
  const { receiverId,senderId } = req.params;
  console.log(senderId)

  const messages = await prisma.message.findMany({
    where: {
      OR: [
        { senderId: parseInt(senderId), receiverId: parseInt(receiverId) },
        { senderId: parseInt(receiverId), receiverId: parseInt(senderId) },
      ],
    },
    orderBy: {
      createdAt: 'asc',
    },
  });

  res.status(200).json(messages);
});

// Get notifications for the user
app.get('/notifications', authenticateToken, async (req, res) => {
  const notifications = await prisma.notification.findMany({
    where: {
      userId: req.userId,
      seen: false,
    },
    orderBy: {
      createdAt: 'asc',
    },
  });

  res.json(notifications);
});

// Mark notifications as seen
app.post('/notifications/mark-seen', authenticateToken, async (req, res) => {
  const { notificationIds } = req.body;
  await prisma.notification.updateMany({
    where: {
      id: { in: notificationIds },
      userId: req.userId,
    },
    data: {
      seen: true,
    },
  });

  res.sendStatus(200);
});



io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  // Store the user's socket ID when they connect
  socket.on('register', (token) => {
    console.log(token);
    const decoded = parseJwt(token);

    if (decoded && decoded.userId) {
      const userId = decoded.userId;
      userSocketMap.set(userId, socket.id);
      console.log(`User ID ${userId} is associated with socket ID ${socket.id}`);
    } else {
      console.error('Invalid token: Cannot decode userId');
    }
  });

  socket.on('message', async ({ token, receiverId, content }) => {
    try {
      const decoded = parseJwt(token);
      if (!decoded) {
        return;
      }
      const senderId = decoded.userId;

      const message = await prisma.message.create({
        data: {
          content,
          senderId,
          receiverId,
        },
      });

      // Emit message to the receiver
      const room = [senderId, receiverId].sort().join('-');
      io.to(room).emit('message', message);

      // Check if the receiver is in the same room
      const clientsInRoom = await io.in(room).allSockets();
      const isReceiverInRoom = Array.from(clientsInRoom).includes(userSocketMap.get(receiverId));

      if (!isReceiverInRoom) {
        // Create and emit notification to the receiver
        const sender = await prisma.user.findUnique({ where: { id: senderId } });
        console.log(sender)
        const content= `New message from ${sender.username}`
          

        // Retrieve the receiver's socket ID
        var receiverSocketId = userSocketMap.get(receiverId);

        if (receiverSocketId) {
          io.to(receiverSocketId).emit('notification', content);
        } else {
          console.log(`No socket ID found for user ${receiverId}`);
        }
      }
    } catch (error) {
      console.error('Error sending message:', error);
    }
  });

  socket.on('onlineusers', async (token) => {
    try {
      console.log("hi")
      console.log(token)
      const decoded = parseJwt(token);
      if (!decoded) {
        return;
      }
      const senderId = decoded.userId;


        // Retrieve the receiver's socket ID
        var receiverSocketId = userSocketMap.get(senderId);
        console.log(receiverSocketId)

        if (receiverSocketId) {
          console.log(userSocketMap)
          const Obj = Object.fromEntries(userSocketMap);
          const users = Object.keys(Obj).map(Number);
          console.log(users)
          io.to(receiverSocketId).emit('onlineusers',users );
        } else {
          console.log(`No socket ID found for user ${receiverId}`);
        }
    
    } catch (error) {
      console.error('Error sending message:', error);
    }
  });

  socket.on('typing', async ({ token, receiverId }) => {
    try {
      const decoded = parseJwt(token);
      if (!decoded) {
        return;
      }
      const senderId = decoded.userId;

     const status="typing..."
     const obj={status,senderId,receiverId}
     console.log(status)

      // Emit message to the receiver
      const room = [senderId, receiverId].sort().join('-');
      io.to(room).emit('typing', obj);

    } catch (error) {
      console.error('Error sending message:', error);
    }
  });

  socket.on('leaveRoom', ({ token, receiverId }) => {
    try
    {
    console.log(token)
    console.log(receiverId)
    const decoded = parseJwt(token);
    console.log(decoded)
    if (!decoded) {
      return;
    }
    const userId = decoded.userId;

    // Leave the previous room
    const previousRoom = socket.rooms.size > 1 ? Array.from(socket.rooms)[1] : null;
    if (previousRoom) {
      socket.leave(previousRoom);
      console.log(`User ${userId} left room ${previousRoom}`);
    }

    }
    catch(err)
    {
      console.log(err)
    }
  });

  socket.on('joinRoom', ({ token, receiverId }) => {
    try
    {
    console.log(token)
    console.log(receiverId)
    const decoded = parseJwt(token);
    console.log(decoded)
    if (!decoded) {
      return;
    }
    const userId = decoded.userId;

    // Leave the previous room
    const previousRoom = socket.rooms.size > 1 ? Array.from(socket.rooms)[1] : null;
    if (previousRoom) {
      socket.leave(previousRoom);
      console.log(`User ${userId} left room ${previousRoom}`);
    }

    // Join the new room
    const newRoom = [userId, receiverId].sort().join('-');
    socket.join(newRoom);
    console.log(`User ${userId} joined room ${newRoom}`);

    }
    catch(err)
    {
      console.log(err)
    }
  });

  socket.on('disconnect', () => {
    console.log('User disconnected');
    console.log(userSocketMap)
    // Remove the user from the mapping if needed
    userSocketMap.forEach((value, key) => {
      if (value === socket.id) {
           console.log("deleted")
        userSocketMap.delete(key);
      }
    });
  });
});

server.listen(3000, () => {
  console.log('listening on *:3000');
});
