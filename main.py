# Blockchain-based Freelance System
# A Flask application with integrated blockchain for freelance task management and payments

# Required packages:
# pip install flask flask-sqlalchemy flask-login web3 pycryptodome

import hashlib
import json
import time
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
from datetime import datetime
from web3 import Web3

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///freelance.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db = SQLAlchemy(app)

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Connect to an Ethereum node (replace with your provider)
# For development, you can use Ganache (http://127.0.0.1:7545)
w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:7545'))


# ============= Database Models =============

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    wallet_address = db.Column(db.String(42))
    is_freelancer = db.Column(db.Boolean, default=False)
    skills = db.Column(db.String(200))
    reputation = db.Column(db.Float, default=0.0)
    tasks_created = db.relationship('Task', backref='client', lazy=True, foreign_keys='Task.client_id')
    tasks_accepted = db.relationship('Task', backref='freelancer', lazy=True, foreign_keys='Task.freelancer_id')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    deadline = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), default='open')  # open, in_progress, completed, disputed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    client_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    freelancer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    contract_address = db.Column(db.String(42))
    blockchain_tx_id = db.Column(db.String(66))


class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'), nullable=False)
    reviewer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reviewed_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ============= Blockchain Implementation =============

class Block:
    def __init__(self, index, previous_hash, timestamp, data, hash):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.data = data
        self.hash = hash


class Blockchain:
    def __init__(self):
        self.chain = []
        self.create_genesis_block()

    def create_genesis_block(self):
        # Create the first block in the chain
        genesis_block = Block(0, "0", time.time(), {
            "transactions": [],
            "message": "Genesis Block of Freelance Platform"
        }, self.calculate_hash(0, "0", time.time(), {
            "transactions": [],
            "message": "Genesis Block of Freelance Platform"
        }))
        self.chain.append(genesis_block)

    @staticmethod
    def calculate_hash(index, previous_hash, timestamp, data):
        # Calculate hash of block
        value = str(index) + str(previous_hash) + str(timestamp) + json.dumps(data, sort_keys=True)
        return hashlib.sha256(value.encode()).hexdigest()

    def get_latest_block(self):
        # Return the last block in the chain
        return self.chain[-1]

    def add_block(self, data):
        # Add a new block to the chain
        latest_block = self.get_latest_block()
        index = latest_block.index + 1
        timestamp = time.time()
        hash = self.calculate_hash(index, latest_block.hash, timestamp, data)
        new_block = Block(index, latest_block.hash, timestamp, data, hash)
        self.chain.append(new_block)
        return new_block

    def is_chain_valid(self):
        # Verify the blockchain integrity
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            # Check if the hash is correct
            if current_block.hash != self.calculate_hash(current_block.index, current_block.previous_hash,
                                                         current_block.timestamp, current_block.data):
                return False

            # Check if the previous hash matches
            if current_block.previous_hash != previous_block.hash:
                return False

        return True

    def get_block_by_index(self, index):
        # Get a block by its index
        if index >= 0 and index < len(self.chain):
            return self.chain[index]
        return None

    def get_task_transactions(self, task_id):
        # Get all transactions related to a task
        transactions = []
        for block in self.chain:
            if 'transactions' in block.data:
                for tx in block.data['transactions']:
                    if 'task_id' in tx and tx['task_id'] == task_id:
                        transactions.append({
                            'block_index': block.index,
                            'transaction': tx,
                            'timestamp': block.timestamp
                        })
        return transactions


# Initialize blockchain
blockchain = Blockchain()

# Smart contract template (simplified for demonstration)
task_contract_template = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract FreelanceTask {
    address payable public client;
    address payable public freelancer;
    uint public amount;
    string public title;
    string public description;
    uint public deadline;
    bool public completed;
    bool public fundsReleased;
    bool public disputed;

    enum TaskStatus { Created, InProgress, Completed, Disputed, Released }
    TaskStatus public status;

    event TaskCreated(address client, string title, uint amount);
    event TaskAccepted(address freelancer);
    event TaskCompleted();
    event FundsReleased();
    event DisputeRaised();

    constructor(
        string memory _title,
        string memory _description,
        uint _deadline,
        address payable _freelancer
    ) payable {
        client = payable(msg.sender);
        amount = msg.value;
        title = _title;
        description = _description;
        deadline = _deadline;
        status = TaskStatus.Created;

        if (_freelancer != address(0)) {
            freelancer = _freelancer;
            status = TaskStatus.InProgress;
            emit TaskAccepted(_freelancer);
        }

        emit TaskCreated(client, title, amount);
    }

    modifier onlyClient() {
        require(msg.sender == client, "Only the client can call this function");
        _;
    }

    modifier onlyFreelancer() {
        require(msg.sender == freelancer, "Only the freelancer can call this function");
        _;
    }

    function acceptTask() external {
        require(status == TaskStatus.Created, "Task already accepted or completed");
        require(freelancer == address(0), "Freelancer already assigned");

        freelancer = payable(msg.sender);
        status = TaskStatus.InProgress;

        emit TaskAccepted(msg.sender);
    }

    function markCompleted() external onlyFreelancer {
        require(status == TaskStatus.InProgress, "Task not in progress");

        status = TaskStatus.Completed;
        completed = true;

        emit TaskCompleted();
    }

    function releaseFunds() external onlyClient {
        require(status == TaskStatus.Completed, "Task not completed");
        require(!fundsReleased, "Funds already released");

        status = TaskStatus.Released;
        fundsReleased = true;
        freelancer.transfer(amount);

        emit FundsReleased();
    }

    function raiseDispute() external {
        require(msg.sender == client || msg.sender == freelancer, "Only client or freelancer can raise disputes");
        require(status == TaskStatus.InProgress || status == TaskStatus.Completed, "Cannot raise dispute at current status");

        status = TaskStatus.Disputed;
        disputed = true;

        emit DisputeRaised();
    }

    function resolveDispute(bool releaseToFreelancer) external onlyClient {
        require(status == TaskStatus.Disputed, "No dispute to resolve");

        if (releaseToFreelancer) {
            freelancer.transfer(amount);
        } else {
            client.transfer(amount);
        }

        fundsReleased = true;
        status = TaskStatus.Released;

        emit FundsReleased();
    }
}
"""


# ============= Flask Routes =============

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def index():
    tasks = Task.query.filter_by(status='open').all()
    return render_template('index.html', tasks=tasks)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        is_freelancer = request.form.get('is_freelancer') == 'on'
        skills = request.form.get('skills')
        wallet_address = request.form.get('wallet_address')

        # Check if username or email already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose another one.')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email already registered. Please use another one.')
            return redirect(url_for('register'))

        # Create new user
        user = User(username=username, email=email, is_freelancer=is_freelancer,
                    skills=skills, wallet_address=wallet_address)
        user.set_password(password)

        db.session.add(user)
        db.session.commit()

        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            flash('Login successful!')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_freelancer:
        # Freelancer view
        available_tasks = Task.query.filter_by(status='open').all()
        accepted_tasks = Task.query.filter_by(freelancer_id=current_user.id).all()
        return render_template('freelancer_dashboard.html',
                               available_tasks=available_tasks,
                               accepted_tasks=accepted_tasks)
    else:
        # Client view
        my_tasks = Task.query.filter_by(client_id=current_user.id).all()
        return render_template('client_dashboard.html', tasks=my_tasks)


@app.route('/create_task', methods=['GET', 'POST'])
@login_required
def create_task():
    if current_user.is_freelancer:
        flash('Only clients can create tasks.')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        price = float(request.form.get('price'))
        deadline_str = request.form.get('deadline')
        deadline = datetime.strptime(deadline_str, '%Y-%m-%d')

        task = Task(
            title=title,
            description=description,
            price=price,
            deadline=deadline,
            client_id=current_user.id
        )

        db.session.add(task)
        db.session.commit()

        # Add to blockchain
        blockchain_data = {
            "transactions": [{
                "type": "task_created",
                "task_id": task.id,
                "client_id": current_user.id,
                "title": title,
                "price": price,
                "timestamp": time.time()
            }]
        }

        block = blockchain.add_block(blockchain_data)

        flash('Task created successfully!')
        return redirect(url_for('dashboard'))

    return render_template('create_task.html')


@app.route('/task/<int:task_id>')
def view_task(task_id):
    task = Task.query.get_or_404(task_id)
    # Get blockchain history for this task
    blockchain_history = blockchain.get_task_transactions(task_id)
    return render_template('task_details.html', task=task, blockchain_history=blockchain_history)


@app.route('/accept_task/<int:task_id>', methods=['POST'])
@login_required
def accept_task(task_id):
    if not current_user.is_freelancer:
        flash('Only freelancers can accept tasks.')
        return redirect(url_for('dashboard'))

    task = Task.query.get_or_404(task_id)

    if task.status != 'open':
        flash('This task is no longer available.')
        return redirect(url_for('dashboard'))

    task.status = 'in_progress'
    task.freelancer_id = current_user.id

    # Add to blockchain
    blockchain_data = {
        "transactions": [{
            "type": "task_accepted",
            "task_id": task.id,
            "freelancer_id": current_user.id,
            "timestamp": time.time()
        }]
    }

    block = blockchain.add_block(blockchain_data)

    db.session.commit()

    flash('Task accepted successfully!')
    return redirect(url_for('dashboard'))


@app.route('/complete_task/<int:task_id>', methods=['POST'])
@login_required
def complete_task(task_id):
    task = Task.query.get_or_404(task_id)

    if task.freelancer_id != current_user.id:
        flash('You can only complete tasks assigned to you.')
        return redirect(url_for('dashboard'))

    if task.status != 'in_progress':
        flash('This task cannot be marked as completed.')
        return redirect(url_for('dashboard'))

    task.status = 'completed'

    # Add to blockchain
    blockchain_data = {
        "transactions": [{
            "type": "task_completed",
            "task_id": task.id,
            "freelancer_id": current_user.id,
            "timestamp": time.time()
        }]
    }

    block = blockchain.add_block(blockchain_data)

    db.session.commit()

    flash('Task marked as completed! Waiting for client approval.')
    return redirect(url_for('dashboard'))


@app.route('/release_payment/<int:task_id>', methods=['POST'])
@login_required
def release_payment(task_id):
    task = Task.query.get_or_404(task_id)

    if task.client_id != current_user.id:
        flash('Only the client can release payment.')
        return redirect(url_for('dashboard'))

    if task.status != 'completed':
        flash('The task must be completed before releasing payment.')
        return redirect(url_for('dashboard'))

    # In a real application, this would involve smart contract interaction
    freelancer = User.query.get(task.freelancer_id)

    # Simulate blockchain transaction
    tx_hash = '0x' + hashlib.sha256(f"{task.id}-{time.time()}".encode()).hexdigest()
    task.blockchain_tx_id = tx_hash

    # Add to blockchain
    blockchain_data = {
        "transactions": [{
            "type": "payment_released",
            "task_id": task.id,
            "client_id": current_user.id,
            "freelancer_id": task.freelancer_id,
            "amount": task.price,
            "transaction_hash": tx_hash,
            "timestamp": time.time()
        }]
    }

    block = blockchain.add_block(blockchain_data)

    # Update freelancer reputation
    freelancer.reputation = (freelancer.reputation + 5) / 2 if freelancer.reputation > 0 else 5

    db.session.commit()

    flash('Payment released successfully!')
    return redirect(url_for('dashboard'))


@app.route('/submit_review/<int:task_id>', methods=['POST'])
@login_required
def submit_review(task_id):
    task = Task.query.get_or_404(task_id)

    if task.client_id != current_user.id and task.freelancer_id != current_user.id:
        flash('Only participants can submit reviews.')
        return redirect(url_for('dashboard'))

    rating = int(request.form.get('rating'))
    comment = request.form.get('comment')

    if current_user.id == task.client_id:
        # Client reviewing freelancer
        reviewer_id = task.client_id
        reviewed_id = task.freelancer_id
    else:
        # Freelancer reviewing client
        reviewer_id = task.freelancer_id
        reviewed_id = task.client_id

    review = Review(
        task_id=task_id,
        reviewer_id=reviewer_id,
        reviewed_id=reviewed_id,
        rating=rating,
        comment=comment
    )

    db.session.add(review)

    # Add to blockchain
    blockchain_data = {
        "transactions": [{
            "type": "review_submitted",
            "task_id": task_id,
            "reviewer_id": reviewer_id,
            "reviewed_id": reviewed_id,
            "rating": rating,
            "timestamp": time.time()
        }]
    }

    block = blockchain.add_block(blockchain_data)

    # Update user reputation
    reviewed_user = User.query.get(reviewed_id)
    all_reviews = Review.query.filter_by(reviewed_id=reviewed_id).all()
    total_rating = sum(r.rating for r in all_reviews)
    reviewed_user.reputation = total_rating / len(all_reviews)

    db.session.commit()

    flash('Review submitted successfully!')
    return redirect(url_for('dashboard'))


# ============= Blockchain API Endpoints =============

@app.route('/api/blockchain/info', methods=['GET'])
def blockchain_info():
    return jsonify({
        'chain_length': len(blockchain.chain),
        'is_valid': blockchain.is_chain_valid(),
        'last_block_hash': blockchain.get_latest_block().hash
    })


@app.route('/api/blockchain/blocks', methods=['GET'])
def get_blocks():
    blocks = []
    for block in blockchain.chain:
        blocks.append({
            'index': block.index,
            'timestamp': block.timestamp,
            'hash': block.hash,
            'previous_hash': block.previous_hash,
            'data': block.data
        })
    return jsonify(blocks)


@app.route('/api/blockchain/task/<int:task_id>', methods=['GET'])
def get_task_blockchain_data(task_id):
    transactions = blockchain.get_task_transactions(task_id)
    return jsonify(transactions)


# ============= Ethereum Smart Contract Integration =============

@app.route('/deploy_contract/<int:task_id>', methods=['POST'])
@login_required
def deploy_contract(task_id):
    task = Task.query.get_or_404(task_id)

    if task.client_id != current_user.id:
        flash('Only the client can deploy the smart contract.')
        return redirect(url_for('dashboard'))

    # In a real application, this would deploy the smart contract to Ethereum
    # For demonstration, we'll just simulate it

    contract_address = '0x' + hashlib.sha256(f"{task.id}-contract-{time.time()}".encode()).hexdigest()[:40]
    task.contract_address = contract_address

    # Add to blockchain
    blockchain_data = {
        "transactions": [{
            "type": "contract_deployed",
            "task_id": task.id,
            "client_id": current_user.id,
            "contract_address": contract_address,
            "timestamp": time.time()
        }]
    }

    block = blockchain.add_block(blockchain_data)

    db.session.commit()

    flash('Smart contract deployed successfully!')
    return redirect(url_for('view_task', task_id=task_id))


# ============= Initialize =============

if __name__ == '__main__':
    with app.app_context():
        # Create database tables
        db.create_all()

    # Run the application
    app.run(debug=True)