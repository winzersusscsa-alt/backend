// backend/server.js
const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');

dotenv.config();
const prisma = new PrismaClient();
const app = express();

app.use(cors());
app.use(express.json());

// ============================================================
// MIDDLEWARE: Check if user is logged in
// ============================================================
function authenticate(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// ============================================================
// AUTHENTICATION ROUTES
// ============================================================

// Login (for both Admin and Dropshipper)
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await prisma.user.findUnique({ where: { username } });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Admin: Create a new Dropshipper User
app.post('/api/admin/users', authenticate, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ error: 'Admin only' });

  const { username, password, phoneNumber } = req.body;
  try {
    const hashed = await bcrypt.hash(password, 10);
    const user = await prisma.user.create({
      data: { username, passwordHash: hashed, phoneNumber, role: 'DROPSHIPPER' },
    });
    res.status(201).json({ message: 'User created', user });
  } catch (error) {
    res.status(400).json({ error: 'Username already exists or invalid data' });
  }
});


// ============================================================
// PRODUCT ROUTES
// ============================================================

// Admin: Add Product
app.post('/api/admin/products', authenticate, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ error: 'Admin only' });

  const { title, description, price, deliveryCharge, deliveryMinDays, deliveryMaxDays, image, note } = req.body;
  try {
    const product = await prisma.product.create({
      data: {
        title,
        description,
        price: parseFloat(price),
        deliveryCharge: parseFloat(deliveryCharge),
        deliveryMinDays: parseInt(deliveryMinDays),
        deliveryMaxDays: parseInt(deliveryMaxDays),
        image,
        note,
        isHidden: false,
      },
    });
    res.status(201).json(product);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Admin: Toggle Hide/Show
app.put('/api/admin/products/:id/toggle-hide', authenticate, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ error: 'Admin only' });

  const { id } = req.params;
  try {
    const product = await prisma.product.findUnique({ where: { id: parseInt(id) } });
    if (!product) return res.status(404).json({ error: 'Product not found' });

    const updated = await prisma.product.update({
      where: { id: parseInt(id) },
      data: { isHidden: !product.isHidden },
    });
    res.json({ message: `Product ${updated.isHidden ? 'Hidden' : 'Available'}`, product: updated });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Dropshipper: Get ONLY Available products (isHidden = false)
app.get('/api/products', async (req, res) => {
  try {
    const products = await prisma.product.findMany({
      where: { isHidden: false },
      orderBy: { createdAt: 'desc' },
    });
    res.json(products);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Admin: Get ALL products (including hidden)
app.get('/api/admin/products', authenticate, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ error: 'Admin only' });
  try {
    const products = await prisma.product.findMany({ orderBy: { createdAt: 'desc' } });
    res.json(products);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================================
// ORDER ROUTES
// ============================================================

// Dropshipper: Add Order
app.post('/api/orders', authenticate, async (req, res) => {
  const { customerName, address, postalCode, phone1, phone2 } = req.body;
  try {
    const lastOrder = await prisma.order.findFirst({ orderBy: { orderNumber: 'desc' } });
    const nextNumber = lastOrder ? lastOrder.orderNumber + 1 : 20001;

    const order = await prisma.order.create({
      data: {
        orderNumber: nextNumber,
        dropshipperId: req.user.id,
        customerName,
        address,
        postalCode,
        phone1,
        phone2,
        status: 'PROCESSING',
      },
    });
    res.status(201).json(order);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Dropshipper: Get My Orders
app.get('/api/orders', authenticate, async (req, res) => {
  try {
    const orders = await prisma.order.findMany({
      where: { dropshipperId: req.user.id },
      orderBy: { createdAt: 'desc' },
    });
    res.json(orders);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ⭐ NEW: Dropshipper: Edit Order (with 2-hour check)
app.put('/api/orders/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  const { customerName, address, postalCode, phone1, phone2 } = req.body;
  try {
    const order = await prisma.order.findUnique({ where: { id: parseInt(id) } });
    if (!order) return res.status(404).json({ error: 'Order not found' });
    if (order.dropshipperId !== req.user.id) return res.status(403).json({ error: 'Not your order' });
    
    const now = new Date();
    const created = new Date(order.createdAt);
    const diffHours = (now - created) / (1000 * 60 * 60);
    if (diffHours > 2) {
      return res.status(403).json({ error: 'Cannot edit after 2 hours' });
    }

    const updated = await prisma.order.update({
      where: { id: parseInt(id) },
      data: { customerName, address, postalCode, phone1, phone2 }
    });
    res.json(updated);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ⭐ NEW: Dropshipper: Delete Order (with 2-hour check)
app.delete('/api/orders/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  try {
    const order = await prisma.order.findUnique({ where: { id: parseInt(id) } });
    if (!order) return res.status(404).json({ error: 'Order not found' });
    if (order.dropshipperId !== req.user.id) return res.status(403).json({ error: 'Not your order' });
    
    const now = new Date();
    const created = new Date(order.createdAt);
    const diffHours = (now - created) / (1000 * 60 * 60);
    if (diffHours > 2) {
      return res.status(403).json({ error: 'Cannot delete after 2 hours' });
    }

    await prisma.order.delete({ where: { id: parseInt(id) } });
    res.json({ message: 'Order deleted' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Admin: Get ALL Orders
app.get('/api/admin/orders', authenticate, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ error: 'Admin only' });
  try {
    const orders = await prisma.order.findMany({
      include: { dropshipper: true },
      orderBy: { createdAt: 'desc' },
    });
    res.json(orders);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Admin: Update Order Status
app.put('/api/admin/orders/:id/status', authenticate, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ error: 'Admin only' });
  const { id } = req.params;
  const { status } = req.body;
  try {
    const order = await prisma.order.update({
      where: { id: parseInt(id) },
      data: { status },
    });
    res.json(order);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================================
// START THE SERVER
// ============================================================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Backend running on port ${PORT}`));
