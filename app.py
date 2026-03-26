from flask import Flask, render_template, request
from scanner import scan_ports
from risk_analyzer import analyze_risk
from attack_simulator import simulate_attack

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def home():
    result = []

    if request.method == 'POST':
        target = request.form['target']
        ports = scan_ports(target)

        for port in ports:
            risk, level = analyze_risk(port)
            attack = simulate_attack(port)

            result.append({
                'port': port,
                'risk': risk,
                'level': level,
                'attack': attack
            })

    return render_template('index.html', result=result)

app.run(debug=True)