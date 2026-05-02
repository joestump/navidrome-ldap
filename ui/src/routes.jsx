import React from 'react'
import { Route } from 'react-router-dom'
import Personal from './personal/Personal'
import Security from './security/Security'

const routes = [
  <Route exact path="/personal" render={() => <Personal />} key={'personal'} />,
  <Route exact path="/security" render={() => <Security />} key={'security'} />,
]

export default routes
