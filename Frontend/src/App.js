import React from 'react';
import { Route, Switch, BrowserRouter } from 'react-router-dom';
import './App.css';
import ProtectedRoute from "./Components/ProtectedRoute"
import SignIn from './Components/SignIn';
import SignUp from './Components/SignUp';
import Home from "./Components/Home"

const App = () => {
  return (
    <BrowserRouter>
      <Switch>
        <Route exact path="/signup" component={SignUp} />
        <Route exact path="/signin" component={SignIn} />
        <ProtectedRoute exact path="/" component={Home}/>
      </Switch>
    </BrowserRouter>
  );
};

export default App;
