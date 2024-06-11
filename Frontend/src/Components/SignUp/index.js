import React, { Component } from 'react';
import './index.css';
import Cookies from 'js-cookie'
import { Link } from 'react-router-dom';

class SignUp extends Component {
  state = {
    username: '',
    password: ''
  };

  handleChange = (event) => {
    this.setState({
      [event.target.name]: event.target.value
    });
  }

  onSubmitSuccess = (jwtToken) => {
    const {history} = this.props

    Cookies.set('jw_token', jwtToken, {
      expires: 1,
      path: '/',
    })
    history.replace('/')
  }

  handleSubmit = async(event) => {
    event.preventDefault();
    const { username, password } = this.state;
    try {
        const response = await fetch("http://localhost:3103/api/user", {
            method: "POST",
            headers: {
            "Content-Type": "application/json",
            },
            body: JSON.stringify({
                username,
                password
            }),
        });
    
        if (response.ok) {
            const data = await response.json();
            console.log("Signup successful:", data);
            console.log(data.token)
            this.onSubmitSuccess(data.token)
    
        } else {
            const errorData = await response.json();
            console.error("Login failed:", errorData.error);
    
        }
        } catch (error) {
        console.error("Error during login:", error.message);
        }
  }

  render() {
    return (
      <div className="signup-container">
        <form className="signup-form" onSubmit={this.handleSubmit}>
          <h2>Sign Up</h2>
          <div className="form-group">
            <label>Username:</label>
            <input type="text" name="username" value={this.state.username} onChange={this.handleChange} required />
          </div>
          <div className="form-group">
            <label>Password:</label>
            <input type="password" name="password" value={this.state.password} onChange={this.handleChange} required />
          </div>
          <button type="submit">Sign Up</button>
          <p>
            Already a user? <Link to="/signin">Sign In</Link>
          </p>
        </form>
      </div>
    );
  }
}

export default SignUp;
