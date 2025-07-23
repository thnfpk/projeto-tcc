// --- 1. IMPORTAÇÕES ---
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const cors = require('cors');
const fs = require('fs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

// --- 2. CONFIGURAÇÕES ---
const app = express();
const port = 3000;
// IMPORTANTE: Troque este segredo por uma frase longa, aleatória e segura!
const JWT_SECRET = 'seu-segredo-super-forte-e-dificil-de-adivinhar-troque-depois';

// Middlewares
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Garante que a pasta 'uploads' exista
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir);
}

// Configuração do Multer para upload de imagens
const storage = multer.diskStorage({
    destination: (req, file, cb) => { cb(null, 'uploads/'); },
    filename: (req, file, cb) => { cb(null, Date.now() + path.extname(file.originalname)); }
});
const upload = multer({ storage: storage });

// Configuração do Nodemailer (LEMBRE-SE DE COLOCAR SUAS CREDENCIAIS REAIS)
const transporter = nodemailer.createTransport({
    host: "sandbox.smtp.mailtrap.io",
    port: 2525,
    auth: {
        user: "SEU_USER_DO_MAILTRAP", // Substitua pelo seu usuário do Mailtrap
        pass: "SUA_SENHA_DO_MAILTRAP" // Substitua pela sua senha do Mailtrap
    }
});

// --- 3. BANCO DE DADOS ---
const db = new sqlite3.Database('./database.db', (err) => {
    if (err) return console.error("Erro ao conectar ao banco de dados:", err.message);
    console.log("Conectado ao banco de dados SQLite.");
    db.run(`CREATE TABLE IF NOT EXISTS usuarios (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL UNIQUE, senha TEXT NOT NULL, nome_usuario TEXT, telefone TEXT, data_nascimento TEXT, foto_perfil_url TEXT, reset_token TEXT, reset_token_expires INTEGER)`);
    db.run(`CREATE TABLE IF NOT EXISTS produtos (id INTEGER PRIMARY KEY AUTOINCREMENT, nome TEXT NOT NULL, descricao TEXT, imagem_url TEXT NOT NULL, usuario_id INTEGER, valor TEXT, FOREIGN KEY (usuario_id) REFERENCES usuarios(id))`);
});

// --- 4. MIDDLEWARE DE AUTENTICAÇÃO ---
function verificarToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: "Acesso negado. Faça login para continuar." });

    jwt.verify(token, JWT_SECRET, (err, usuario) => {
        if (err) return res.status(403).json({ message: "Token inválido ou expirado." });
        req.usuario = usuario;
        next();
    });
}

// --- 5. ROTAS DA API ---

// -- ROTAS DE AUTENTICAÇÃO E USUÁRIO --
app.post('/registrar', async (req, res) => {
    const { email, senha } = req.body;
    if (!email || !senha) return res.status(400).json({ message: 'Email e senha são obrigatórios.' });
    try {
        const senhaHash = await bcrypt.hash(senha, 10);
        db.run('INSERT INTO usuarios (email, senha) VALUES (?, ?)', [email, senhaHash], function (err) {
            if (err) {
                if (err.message.includes('UNIQUE')) return res.status(409).json({ message: 'Este e-mail já está cadastrado.' });
                return res.status(500).json({ message: 'Erro ao registrar usuário.' });
            }
            res.status(201).json({ message: 'Usuário registrado com sucesso!' });
        });
    } catch (error) { res.status(500).json({ message: 'Erro interno do servidor.' }); }
});

app.post('/login', (req, res) => {
    const { email, senha } = req.body;
    db.get('SELECT * FROM usuarios WHERE email = ?', [email], async (err, user) => {
        if (err || !user) return res.status(401).json({ message: 'Email ou senha inválidos.' });
        const senhaValida = await bcrypt.compare(senha, user.senha);
        if (!senhaValida) return res.status(401).json({ message: 'Email ou senha inválidos.' });
        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '3h' });
        res.status(200).json({ message: 'Login bem-sucedido!', token: token });
    });
});

app.get('/perfil', verificarToken, (req, res) => {
    db.get("SELECT id, email, nome_usuario, telefone, data_nascimento, foto_perfil_url FROM usuarios WHERE id = ?", [req.usuario.id], (err, row) => {
        if (err) return res.status(500).json({ message: "Erro ao buscar perfil." });
        if (!row) return res.status(404).json({ message: "Usuário não encontrado." });
        res.json(row);
    });
});

app.put('/perfil', verificarToken, upload.single('foto_perfil'), async (req, res) => {
    const { nome_usuario, telefone, data_nascimento, senha } = req.body;
    const usuarioId = req.usuario.id;
    let campos = [], valores = [];
    if (nome_usuario) { campos.push("nome_usuario = ?"); valores.push(nome_usuario); }
    if (telefone) { campos.push("telefone = ?"); valores.push(telefone); }
    if (data_nascimento) { campos.push("data_nascimento = ?"); valores.push(data_nascimento); }
    if (req.file) { campos.push("foto_perfil_url = ?"); valores.push(`/uploads/${req.file.filename}`); }
    if (senha) {
        const hash = await bcrypt.hash(senha, 10);
        campos.push("senha = ?"); valores.push(hash);
    }
    if (campos.length === 0) return res.json({ message: "Nenhuma informação para atualizar." });
    db.run(`UPDATE usuarios SET ${campos.join(', ')} WHERE id = ?`, [...valores, usuarioId], (err) => {
        if (err) return res.status(500).json({ message: "Erro ao atualizar perfil." });
        res.json({ message: "Perfil atualizado com sucesso!" });
    });
});

// -- ROTAS DE PRODUTOS --
app.get('/produtos', (req, res) => {
    db.all("SELECT p.*, u.nome_usuario FROM produtos p JOIN usuarios u ON p.usuario_id = u.id ORDER BY p.id DESC", [], (err, rows) => {
        if (err) return res.status(500).json({ message: "Erro ao buscar produtos." });
        res.json(rows);
    });
});

app.get('/produtos/:id', (req, res) => {
    db.get(`SELECT p.*, u.nome_usuario FROM produtos p LEFT JOIN usuarios u ON p.usuario_id = u.id WHERE p.id = ?`, [req.params.id], (err, row) => {
        if (err) return res.status(500).json({ message: "Erro no banco de dados." });
        if (!row) return res.status(404).json({ message: "Produto não encontrado." });
        res.json(row);
    });
});

app.post('/produtos', verificarToken, upload.single('imagem'), (req, res) => {
    const { nome, descricao, valor } = req.body;
    if (!nome || !valor || !req.file) return res.status(400).json({ message: "Nome, valor e imagem são obrigatórios." });
    const imagem_url = `/uploads/${req.file.filename}`;
    db.run(`INSERT INTO produtos (nome, descricao, imagem_url, usuario_id, valor) VALUES (?, ?, ?, ?, ?)`, [nome, descricao, imagem_url, req.usuario.id, valor], function (err) {
        if (err) return res.status(500).json({ message: "Erro ao cadastrar o produto." });
        res.status(201).json({ message: "Produto cadastrado com sucesso!", produtoId: this.lastID });
    });
});

app.put('/produtos/:id', verificarToken, upload.single('imagem'), (req, res) => {
    const { nome, valor, descricao } = req.body;
    db.get('SELECT usuario_id FROM produtos WHERE id = ?', [req.params.id], (err, row) => {
        if (err || !row) return res.status(404).json({ message: 'Produto não encontrado.' });
        if (row.usuario_id !== req.usuario.id) return res.status(403).json({ message: 'Você não tem permissão para editar este produto.' });
        let campos = [], valores = [];
        if (nome) { campos.push("nome = ?"); valores.push(nome); }
        if (valor) { campos.push("valor = ?"); valores.push(valor); }
        if (descricao) { campos.push("descricao = ?"); valores.push(descricao); }
        if (req.file) { campos.push("imagem_url = ?"); valores.push(`/uploads/${req.file.filename}`); }
        if (campos.length === 0) return res.json({ message: "Nenhuma informação para atualizar." });
        db.run(`UPDATE produtos SET ${campos.join(', ')} WHERE id = ?`, [...valores, req.params.id], (err) => {
            if (err) return res.status(500).json({ message: "Erro ao atualizar o produto." });
            res.json({ message: "Produto atualizado com sucesso!" });
        });
    });
});

app.delete('/produtos/:id', verificarToken, (req, res) => {
    db.get('SELECT usuario_id, imagem_url FROM produtos WHERE id = ?', [req.params.id], (err, row) => {
        if (err || !row) return res.status(404).json({ message: 'Produto não encontrado.' });
        if (row.usuario_id !== req.usuario.id) return res.status(403).json({ message: 'Você não tem permissão para deletar este produto.' });
        db.run('DELETE FROM produtos WHERE id = ?', [req.params.id], (err) => {
            if (err) return res.status(500).json({ message: 'Erro ao deletar o produto.' });
            if (row.imagem_url) fs.unlink(path.join(__dirname, row.imagem_url), e => e && console.error("Erro ao deletar arquivo:", e));
            res.json({ message: 'Produto deletado com sucesso.' });
        });
    });
});

app.get('/meus-anuncios', verificarToken, (req, res) => {
    db.all("SELECT * FROM produtos WHERE usuario_id = ? ORDER BY id DESC", [req.usuario.id], (err, rows) => {
        if (err) return res.status(500).json({ message: 'Erro ao buscar seus anúncios.' });
        res.json(rows);
    });
});

// -- ROTAS DE RECUPERAÇÃO DE SENHA --
app.post('/esqueci-senha', (req, res) => {
    const { email } = req.body;
    db.get('SELECT * FROM usuarios WHERE email = ?', [email], async (err, user) => {
        if (!user) return res.json({ message: 'Se um usuário com este e-mail existir, um código será enviado.' });
        const codigo = crypto.randomInt(100000, 999999).toString();
        const expires = Date.now() + 600000; // 10 minutos
        db.run('UPDATE usuarios SET reset_token = ?, reset_token_expires = ? WHERE email = ?', [codigo, expires, email]);
        try {
            await transporter.sendMail({ to: email, from: '"EcoKids Baby" <nao-responda@ecokids.com>', subject: 'Seu Código de Recuperação', html: `<p>Seu código para redefinir a senha é: <strong>${codigo}</strong></p><p>Válido por 10 minutos.</p>` });
            res.json({ message: 'Se um usuário com este e-mail existir, um código será enviado.' });
        } catch (error) { res.status(500).json({ message: 'Não foi possível enviar o e-mail de recuperação.' }); }
    });
});

app.post('/redefinir-senha', async (req, res) => {
    const { email, codigo, novaSenha } = req.body;
    if (!email || !codigo || !novaSenha) return res.status(400).json({ message: "Todos os campos são obrigatórios." });
    const sql = 'SELECT * FROM usuarios WHERE email = ? AND reset_token = ? AND reset_token_expires > ?';
    db.get(sql, [email, codigo, Date.now()], async (err, user) => {
        if (err || !user) return res.status(400).json({ message: "Código inválido ou expirado." });
        const senhaHash = await bcrypt.hash(novaSenha, 10);
        db.run('UPDATE usuarios SET senha = ?, reset_token = NULL, reset_token_expires = NULL WHERE id = ?', [senhaHash, user.id], (err) => {
            if (err) return res.status(500).json({ message: "Erro ao atualizar a senha." });
            res.json({ message: "Senha alterada com sucesso!" });
        });
    });
});

// --- 6. INICIAR O SERVIDOR ---
app.listen(port, () => {
    console.log(`Backend rodando em http://localhost:${port}`);
});