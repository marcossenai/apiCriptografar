const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const app = express();
const port = process.env.PORT || 3000;

const API_KEY = '1234567890abcdef';
const algorithm = 'aes-256-cbc'; // Algoritmo de criptografia
const key = crypto.randomBytes(32); // Chave de 256 bits

app.use(express.json());
app.use(cors());

// Middleware de autenticação de chave de API
const authenticateAPIKey = (req, res, next) => {
  const apiKey = req.header('x-api-key');

  if (!apiKey || apiKey !== API_KEY) {
    return res.status(403).json({ message: 'Chave de API inválida.' });
  }

  next();
};

app.use(authenticateAPIKey);

// Função para criptografar mensagem
const encryptMessage = (message) => {
  const iv = crypto.randomBytes(16); // Gerar um IV aleatório para cada criptografia
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  let encrypted = cipher.update(message, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return { iv: iv.toString('hex'), encryptedData: encrypted };
};

// Função para descriptografar mensagem
const decryptMessage = (iv, encryptedData) => {
  const decipher = crypto.createDecipheriv(algorithm, key, Buffer.from(iv, 'hex'));
  let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
};

// Endpoint para criptografar uma mensagem
app.post('/api/encrypt', (req, res) => {
  const { message } = req.body;
  if (!message) {
    return res.status(400).json({ message: 'Mensagem é obrigatória.' });
  }

  const encryptedMessage = encryptMessage(message);
  res.status(200).json(encryptedMessage);
});

// Endpoint para descriptografar uma mensagem
app.post('/api/decrypt', (req, res) => {
  const { iv, encryptedData } = req.body;
  if (!iv || !encryptedData) {
    return res.status(400).json({ message: 'IV e dados criptografados são obrigatórios.' });
  }

  const decryptedMessage = decryptMessage(iv, encryptedData);
  res.status(200).json({ message: decryptedMessage });
});

// Inicia o servidor
app.listen(port, () => {
  console.log(`Servidor rodando em http://localhost:${port}`);
});
