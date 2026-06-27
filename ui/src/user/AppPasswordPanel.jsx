import React, { useCallback, useEffect, useState } from 'react'
import {
  Box,
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogContentText,
  DialogTitle,
  IconButton,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Tooltip,
  Typography,
} from '@material-ui/core'
import DeleteOutlineIcon from '@material-ui/icons/DeleteOutline'
import { useNotify, useTranslate } from 'react-admin'
import { makeStyles } from '@material-ui/core/styles'
import httpClient from '../dataProvider/httpClient'
import { REST_URL } from '../consts'

const useStyles = makeStyles((theme) => ({
  root: {
    width: '100%',
    marginTop: theme.spacing(3),
    padding: theme.spacing(2),
    boxSizing: 'border-box',
  },
  header: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    flexWrap: 'wrap',
    gap: theme.spacing(1),
    marginBottom: theme.spacing(1),
  },
  empty: {
    color: theme.palette.text.secondary,
    fontStyle: 'italic',
    padding: theme.spacing(2, 0),
  },
  tableWrap: {
    width: '100%',
    overflowX: 'auto',
  },
  secret: {
    display: 'block',
    width: '100%',
    marginTop: theme.spacing(1),
    padding: theme.spacing(1.5),
    fontFamily: 'monospace',
    fontSize: '1rem',
    textAlign: 'left',
    wordBreak: 'break-all',
    backgroundColor: theme.palette.action.hover,
    border: `1px solid ${theme.palette.divider}`,
    borderRadius: theme.shape.borderRadius,
    color: theme.palette.text.primary,
    cursor: 'pointer',
    '&:hover, &:focus-visible': {
      backgroundColor: theme.palette.action.selected,
      borderColor: theme.palette.primary.main,
      outline: 'none',
    },
  },
}))

// AppPasswordPanel renders a list of the user's app passwords with a button to
// generate a new one and a per-row revoke button. The plaintext secret is
// shown exactly once, in a modal, immediately after generation. After the
// modal is dismissed the secret is unrecoverable from the UI.
export const AppPasswordPanel = ({ userId }) => {
  const classes = useStyles()
  const translate = useTranslate()
  const notify = useNotify()

  const [items, setItems] = useState([])
  const [loading, setLoading] = useState(false)
  const [createOpen, setCreateOpen] = useState(false)
  const [newName, setNewName] = useState('')
  const [creating, setCreating] = useState(false)
  const [generated, setGenerated] = useState(null)
  const [revokeTarget, setRevokeTarget] = useState(null)
  const [revoking, setRevoking] = useState(false)

  const reload = useCallback(async () => {
    if (!userId) return
    setLoading(true)
    try {
      const { json } = await httpClient(
        `${REST_URL}/user/${userId}/app-password`,
      )
      setItems(Array.isArray(json) ? json : [])
    } catch (e) {
      notify('resources.user.notifications.appPasswordLoadError', 'warning')
    } finally {
      setLoading(false)
    }
  }, [userId, notify])

  useEffect(() => {
    reload()
  }, [reload])

  const handleCreate = async () => {
    if (!newName.trim()) return
    setCreating(true)
    try {
      const { json } = await httpClient(
        `${REST_URL}/user/${userId}/app-password`,
        {
          method: 'POST',
          body: JSON.stringify({ name: newName.trim() }),
        },
      )
      setGenerated(json)
      setCreateOpen(false)
      setNewName('')
      await reload()
    } catch (e) {
      const msg =
        e?.body?.toString?.() ||
        e?.message ||
        translate('resources.user.notifications.appPasswordCreateError')
      notify(msg, 'warning')
    } finally {
      setCreating(false)
    }
  }

  const handleRevokeConfirmed = async () => {
    if (!revokeTarget) return
    setRevoking(true)
    try {
      await httpClient(
        `${REST_URL}/user/${userId}/app-password/${revokeTarget.id}`,
        { method: 'DELETE' },
      )
      notify('resources.user.notifications.appPasswordRevoked', 'info')
      setRevokeTarget(null)
      await reload()
    } catch (e) {
      notify('resources.user.notifications.appPasswordRevokeError', 'warning')
    } finally {
      setRevoking(false)
    }
  }

  const handleCopy = (value) => {
    if (navigator?.clipboard?.writeText) {
      navigator.clipboard.writeText(value)
      notify('resources.user.notifications.appPasswordCopied', 'info')
    }
  }

  const handleSecretKeyDown = (value) => (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault()
      handleCopy(value)
    }
  }

  const formatDate = (d) => (d ? new Date(d).toLocaleString() : '—')

  return (
    <Paper className={classes.root} elevation={0} variant="outlined">
      <Box className={classes.header}>
        <Typography variant="h6">
          {translate('resources.user.fields.appPasswords')}
        </Typography>
        <Button
          variant="contained"
          color="primary"
          onClick={() => setCreateOpen(true)}
        >
          {translate('resources.user.actions.generateAppPassword')}
        </Button>
      </Box>

      {!loading && items.length === 0 && (
        <Typography className={classes.empty}>
          {translate('resources.user.message.appPasswordsEmpty')}
        </Typography>
      )}

      {items.length > 0 && (
        <TableContainer className={classes.tableWrap}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>
                  {translate('resources.user.fields.appPasswordName')}
                </TableCell>
                <TableCell>
                  {translate('resources.user.fields.appPasswordCreatedAt')}
                </TableCell>
                <TableCell>
                  {translate('resources.user.fields.appPasswordLastUsedAt')}
                </TableCell>
                <TableCell>
                  {translate('resources.user.fields.appPasswordStatus')}
                </TableCell>
                <TableCell align="right" />
              </TableRow>
            </TableHead>
            <TableBody>
              {items.map((row) => (
                <TableRow key={row.id}>
                  <TableCell>{row.name}</TableCell>
                  <TableCell>{formatDate(row.createdAt)}</TableCell>
                  <TableCell>{formatDate(row.lastUsedAt)}</TableCell>
                  <TableCell>
                    {row.revokedAt
                      ? translate('resources.user.message.appPasswordRevoked')
                      : translate('resources.user.message.appPasswordActive')}
                  </TableCell>
                  <TableCell align="right">
                    {!row.revokedAt && (
                      <Tooltip
                        title={translate(
                          'resources.user.actions.revokeAppPassword',
                        )}
                      >
                        <IconButton
                          size="small"
                          onClick={() => setRevokeTarget(row)}
                        >
                          <DeleteOutlineIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      <Dialog
        open={createOpen}
        onClose={() => !creating && setCreateOpen(false)}
      >
        <DialogTitle>
          {translate('resources.user.actions.generateAppPassword')}
        </DialogTitle>
        <DialogContent>
          <DialogContentText>
            {translate('resources.user.message.appPasswordCreatePrompt')}
          </DialogContentText>
          <TextField
            autoFocus
            fullWidth
            margin="dense"
            label={translate('resources.user.fields.appPasswordName')}
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            disabled={creating}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateOpen(false)} disabled={creating}>
            {translate('ra.action.cancel')}
          </Button>
          <Button
            onClick={handleCreate}
            color="primary"
            disabled={creating || !newName.trim()}
          >
            {translate('ra.action.create')}
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog open={!!generated} onClose={() => setGenerated(null)} fullWidth>
        <DialogTitle>
          {translate('resources.user.message.appPasswordCreated')}
        </DialogTitle>
        <DialogContent>
          <DialogContentText>
            {translate('resources.user.message.appPasswordOneTime')}
          </DialogContentText>
          {generated && (
            <Tooltip
              title={translate('resources.user.message.appPasswordClickToCopy')}
              placement="top"
            >
              <Box
                component="div"
                role="button"
                tabIndex={0}
                aria-label={translate(
                  'resources.user.message.appPasswordClickToCopy',
                )}
                className={classes.secret}
                onClick={() => handleCopy(generated.secret)}
                onKeyDown={handleSecretKeyDown(generated.secret)}
              >
                {generated.secret}
              </Box>
            </Tooltip>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setGenerated(null)} color="primary">
            {translate('ra.action.close')}
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog
        open={!!revokeTarget}
        onClose={() => !revoking && setRevokeTarget(null)}
      >
        <DialogTitle>
          {translate('resources.user.message.appPasswordConfirmRevokeTitle')}
        </DialogTitle>
        <DialogContent>
          <DialogContentText>
            {translate('resources.user.message.appPasswordConfirmRevokeBody', {
              name: revokeTarget?.name || '',
            })}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setRevokeTarget(null)} disabled={revoking}>
            {translate('ra.action.cancel')}
          </Button>
          <Button
            onClick={handleRevokeConfirmed}
            color="secondary"
            disabled={revoking}
          >
            {translate('resources.user.actions.revokeAppPassword')}
          </Button>
        </DialogActions>
      </Dialog>
    </Paper>
  )
}

export default AppPasswordPanel
