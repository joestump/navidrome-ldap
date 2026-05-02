import { Title, useTranslate } from 'react-admin'
import { Card, CardContent, Typography } from '@material-ui/core'
import { makeStyles } from '@material-ui/core/styles'
import { AppPasswordPanel } from '../user/AppPasswordPanel'

const useStyles = makeStyles((theme) => ({
  root: {
    marginTop: theme.spacing(2),
  },
  intro: {
    marginBottom: theme.spacing(2),
    color: theme.palette.text.secondary,
  },
}))

const Security = () => {
  const translate = useTranslate()
  const classes = useStyles()
  const userId = localStorage.getItem('userId')

  return (
    <Card className={classes.root}>
      <Title title={'Navidrome - ' + translate('menu.security.name')} />
      <CardContent>
        <Typography variant="body2" className={classes.intro}>
          {translate('menu.security.intro')}
        </Typography>
        <AppPasswordPanel userId={userId} />
      </CardContent>
    </Card>
  )
}

export default Security
