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
// ADMIN: USER MANAGEMENT
// ============================================================

// Admin: Get All Users
app.get('/api/admin/users', authenticate, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ error: 'Admin only' });
  try {
    const users = await prisma.user.findMany({
      where: { role: 'DROPSHIPPER' },
      select: {
        id: true,
        username: true,
        phoneNumber: true,
        role: true,
        createdAt: true
      },
      orderBy: { createdAt: 'desc' }
    });
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Admin: Get Single User
app.get('/api/admin/users/:id', authenticate, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ error: 'Admin only' });
  const { id } = req.params;
  try {
    const user = await prisma.user.findUnique({
      where: { id: parseInt(id) },
      select: {
        id: true,
        username: true,
        phoneNumber: true,
        role: true,
        createdAt: true
      }
    });
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Admin: Update User
app.put('/api/admin/users/:id', authenticate, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ error: 'Admin only' });
  const { id } = req.params;
  const { username, password, phoneNumber } = req.body;
  try {
    const data = { username, phoneNumber };
    if (password && password.trim() !== '') {
      data.passwordHash = await bcrypt.hash(password, 10);
    }
    const user = await prisma.user.update({
      where: { id: parseInt(id) },
      data
    });
    res.json({ message: 'User updated', user });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Admin: Delete User
app.delete('/api/admin/users/:id', authenticate, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ error: 'Admin only' });
  const { id } = req.params;
  try {
    // Prevent admin from deleting themselves
    if (parseInt(id) === req.user.id) {
      return res.status(400).json({ error: 'Cannot delete your own account' });
    }
    await prisma.user.delete({
      where: { id: parseInt(id) }
    });
    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// ============================================================
// BANK DETAILS & PAYMENTS
// ============================================================

// Dropshipper: Save or Update Bank Details
app.post('/api/bank-details', authenticate, async (req, res) => {
  const { bankName, branch, accountHolder, accountNumber } = req.body;
  try {
    // Check if bank details already exist for this user
    const existing = await prisma.bankDetail.findUnique({
      where: { dropshipperId: req.user.id }
    });

    let bankDetail;
    if (existing) {
      // Update existing
      bankDetail = await prisma.bankDetail.update({
        where: { dropshipperId: req.user.id },
        data: { bankName, branch, accountHolder, accountNumber }
      });
    } else {
      // Create new
      bankDetail = await prisma.bankDetail.create({
        data: {
          dropshipperId: req.user.id,
          bankName,
          branch,
          accountHolder,
          accountNumber
        }
      });
    }
    res.json({ message: 'Bank details saved successfully', bankDetail });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Dropshipper: Get My Bank Details
app.get('/api/bank-details', authenticate, async (req, res) => {
  try {
    const bankDetail = await prisma.bankDetail.findUnique({
      where: { dropshipperId: req.user.id }
    });
    res.json(bankDetail || null);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Dropshipper: Get My Payment History
app.get('/api/payments', authenticate, async (req, res) => {
  try {
    const payments = await prisma.paymentRecord.findMany({
      where: { dropshipperId: req.user.id },
      orderBy: { paymentDate: 'desc' }
    });
    res.json(payments);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Admin: Add Payment (sends money to dropshipper)
app.post('/api/admin/payments', authenticate, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ error: 'Admin only' });
  
  const { dropshipperId, paymentDate, amount, accountNumber, proofUrl } = req.body;
  try {
    const payment = await prisma.paymentRecord.create({
      data: {
        dropshipperId: parseInt(dropshipperId),
        paymentDate: new Date(paymentDate),
        amount: parseFloat(amount),
        accountNumber,
        proofUrl: proofUrl || ''
      }
    });
    res.status(201).json({ message: 'Payment record added', payment });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Admin: Get All Payment Records (with dropshipper info)
app.get('/api/admin/payments', authenticate, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ error: 'Admin only' });
  try {
    const payments = await prisma.paymentRecord.findMany({
      include: { dropshipper: true },
      orderBy: { paymentDate: 'desc' }
    });
    res.json(payments);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Admin: Get All Bank Details
app.get('/api/admin/bank-details', authenticate, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ error: 'Admin only' });
  try {
    const bankDetails = await prisma.bankDetail.findMany({
      include: { dropshipper: true }
    });
    res.json(bankDetails);
  } catch (error) {
    res.status(500).json({ error: error.message });
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
// PRODUCT MANAGEMENT (Admin) - EDIT & DELETE
// ============================================================

// Admin: Edit Product (Update all fields)
app.put('/api/admin/products/:id', authenticate, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ error: 'Admin only' });

  const { id } = req.params;
  const { title, description, price, deliveryCharge, deliveryMinDays, deliveryMaxDays, image, note, isHidden } = req.body;

  try {
    const product = await prisma.product.update({
      where: { id: parseInt(id) },
      data: {
        title,
        description,
        price: parseFloat(price),
        deliveryCharge: parseFloat(deliveryCharge),
        deliveryMinDays: parseInt(deliveryMinDays),
        deliveryMaxDays: parseInt(deliveryMaxDays),
        image,
        note,
        isHidden: isHidden !== undefined ? isHidden : false
      }
    });
    res.json({ message: 'Product updated successfully', product });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Admin: Delete Product
app.delete('/api/admin/products/:id', authenticate, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ error: 'Admin only' });

  const { id } = req.params;

  try {
    await prisma.product.delete({
      where: { id: parseInt(id) }
    });
    res.json({ message: 'Product deleted successfully' });
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

// Admin: Update Full Order (all fields)
app.put('/api/admin/orders/:id', authenticate, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ error: 'Admin only' });
  
  const { id } = req.params;
  const { customerName, address, postalCode, phone1, phone2, status } = req.body;
  
  try {
    const order = await prisma.order.update({
      where: { id: parseInt(id) },
      data: {
        customerName,
        address,
        postalCode,
        phone1,
        phone2,
        status
      }
    });
    res.json({ message: 'Order updated successfully', order });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// Admin: Bulk Delete Orders
app.delete('/api/admin/orders/bulk', authenticate, async (req, res) => {
  if (req.user.role !== 'ADMIN') return res.status(403).json({ error: 'Admin only' });
  
  const { orderIds } = req.body;
  if (!orderIds || !Array.isArray(orderIds) || orderIds.length === 0) {
    return res.status(400).json({ error: 'Please provide an array of order IDs' });
  }

  try {
    const deleted = await prisma.order.deleteMany({
      where: {
        id: { in: orderIds.map(id => parseInt(id)) }
      }
    });
    res.json({ message: `${deleted.count} orders deleted successfully`, count: deleted.count });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================================
// START THE SERVER
// ============================================================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Backend running on port ${PORT}`));
