from flask import Flask, render_template, request, jsonify
import math

def Attack_Vector(a_v):
    if a_v == "network":
        av = 0.85
    elif a_v == "adjecent":
        av = 0.62
    elif a_v == "local":
        av = 0.55
    elif a_v == "physical":
        av = 0.2
    return av

def Attack_Complexity(a_c):
    if a_c == "low":
        ac = 0.77
    elif a_c == "high":
        ac = 0.44
    return ac

def Privileges_Required(scope, p_r):
    if p_r == "none":
        pr = 0.85
    elif p_r == "low":
        if scope == "changed":
            pr = 0.68
        elif scope == "unchanged":
            pr = 0.62
    elif p_r == "high":
        if scope == "changed":
            pr = 0.5
        elif scope == "unchanged":
            pr = 0.27
    return pr

def User_Interaction(u_i):
    if u_i == "none":
        ui = 0.85
    elif u_i == "required":
        ui = 0.62
    return ui

def Confidentiality(confidentiality):
    if confidentiality == "high":
        conf = 0.56
    elif confidentiality == "low":
        conf = 0.22
    elif confidentiality == "none":
        conf = 0
    return conf

def Integrity(integrity):
    if integrity == "high":
        integ = 0.56
    elif integrity == "low":
        integ = 0.22
    elif integrity == "none":
        integ = 0
    return integ

def Availability(availability):
    if availability == "high":
        avail = 0.56
    elif availability == "low":
        avail = 0.22
    elif availability == "none":
        avail = 0
    return avail

def ISS(conf, integ, avail):
    iss = 1-((1 - conf) * (1 - integ) * (1 - avail))
    return iss

def Impact(scope, conf, integ, avail):
    iss = ISS(conf, integ, avail)
    if scope == "unchanged":
        impact = 6.42 * iss
    elif scope == "changed":
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    return impact

def Exploitablity(av, ac, pr, ui):
    exploitability = 8.22 * av * ac * pr * ui
    return exploitability

def roundup(x, decimals):
    factor = 10 ** decimals
    return math.ceil(x * factor) / factor

def Base_Score(av, ac, scope, pr, ui, conf, integ, avail):
    impact = Impact(scope, conf, integ, avail)
    exploitability = Exploitablity(av, ac, pr, ui)
    if impact <= 0:
        base_score = 0
    elif scope == "unchanged":
        base_score = roundup (min ((impact + exploitability), 10), 1)
    elif scope == "changed":
        base_score = roundup (min (1.08 * (impact + exploitability), 10), 1)
    return base_score

def value(a_v, a_c, scope, p_r, u_i, confidentiality, integrity, availability):
    av = Attack_Vector(a_v)
    ac = Attack_Complexity(a_c)
    pr = Privileges_Required(scope, p_r)
    ui = User_Interaction(u_i)
    conf = Confidentiality(confidentiality)
    integ = Integrity(integrity)
    avail = Availability(availability)
    return av, ac, scope, pr, ui, conf, integ, avail


app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/calculate', methods=['POST'])
def calculate():
    try:
        # Extract form data
        data = request.form
        a_v = str(data['av'])
        a_c = str(data['ac'])
        p_r = str(data.get('pr'))
        u_i = str(data.get('ui'))
        scope = data.get('s')
        confidentiality = str(data.get('c'))
        integrity = str(data.get('i'))
        availability = str(data.get('a'))

        av, ac, scope, pr, ui, conf, integ, avail = value(a_v, a_c, scope, p_r, u_i, confidentiality, integrity, availability)

        # Calculate CVSS score
        score = Base_Score(av, ac, scope, pr, ui, conf, integ, avail)
        return jsonify({'score': score})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True)