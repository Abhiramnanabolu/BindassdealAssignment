import React, { Component } from 'react';
import './index.css';
import { Link } from 'react-router-dom';
import Cookies from 'js-cookie';

class SignIn extends Component {
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

  handleSubmit = async(e) => {
    e.preventDefault();
    const { username, password } = this.state;
    try {
      const response = await fetch('http://localhost:3103/api/signin', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            username,
            password
        }),
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error);
      }

      const data = await response.json();
      console.log("Signup successful:", data);
      this.onSubmitSuccess(data.token)
    } catch (err) {
      console.log(err.message);
    }
  };


  render() {
    return (
      <div className="signin-container">
        <form className="signin-form" onSubmit={this.handleSubmit}>
          <h2>Sign In</h2>
          <div className="form-group">
            <label>Username:</label>
            <input type="text" name="username" value={this.state.username} onChange={this.handleChange} required />
          </div>
          <div className="form-group">
            <label>Password:</label>
            <input type="password" name="password" value={this.state.password} onChange={this.handleChange} required />
          </div>
          <button type="submit">Sign In</button>
          <p>
            Not a user? <Link to="/signup">Sign Up</Link>
          </p>
        </form>
      </div>
    );
  }
}

export default SignIn;
